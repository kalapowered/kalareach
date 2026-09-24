//! The two plugin method groups, as the control daemon serves them.
//!
//! The catalogue's own rules are the runtime crate's and are tested there. What this covers is the
//! daemon's half: that both groups reach the module at all, that every method in them has one
//! exhaustive generated authority entry, that a request for another environment is refused before
//! anything is read, and that the answers carry the checks section 23 names for those two rows.

use std::path::Path;

use std::sync::Arc;

use kr_controller::catalogue::{Admission, CatalogueModule};
use kr_controller::sharing::{
    CatalogueTrustPlan, ConfirmedAction, OwnerConfirmations, PluginGrantPlan, PluginInstallPlan,
};
use kr_plugin_catalogue::{
    Authority, CapabilityCeiling, CatalogueError, CatalogueResult, Effect, Enrolment, Owner,
    RepositoryId, RepositoryKind,
};
use kr_protocol::actor::ActorIngress;
use kr_protocol::catalogue as wire;
use kr_protocol::envelope::{
    ActionTarget, ControlFrame, MutationRequest, Outcome, ParamsValue, Request,
};
use kr_protocol::error::ErrorCode;
use kr_protocol::ids::{
    ActionId, ActionWindowId, ActorId, EnvironmentId, PluginId, RepositoryGeneration, RequestId,
};
use kr_protocol::method::{Method, MethodName, MethodVersion};
use kr_protocol::pairing::{ConfirmationChannel, OwnerConfirmationProof, SensitiveAction};
use kr_protocol::scalars::{Digest256, DurationMs, Nullable, U64};

/// Where the copied development generation lives inside this checkout.
fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins/catalogue/development")
}

struct Host {
    _temp: kr_ipc::testing::TempHost,
    module: CatalogueModule,
    environment_id: EnvironmentId,
    working: std::path::PathBuf,
    _working_temp: tempfile::TempDir,
    ceremony: Ceremony,
}

impl Host {
    fn confirmations(&self) -> &dyn OwnerConfirmations {
        &self.ceremony
    }
}

/// This host's clock, derived the way the daemon derives its own.
///
/// A fixed boot value would make every confirmation built here look like one from another boot.
/// A test that lets a confirmation expire moves the clock on rather than waiting two minutes.
#[derive(Debug, Default)]
struct Clock {
    ahead_ms: Arc<std::sync::atomic::AtomicU64>,
}

impl Clock {
    fn ahead(&self) -> u64 {
        self.ahead_ms.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl kr_pairing::platform::PairingClock for Clock {
    fn monotonic_ms(&self) -> u64 {
        kr_ipc::clock::SharedClock::boot_elapsed_ms(&kr_ipc::clock::SystemSharedClock)
            + self.ahead()
    }

    fn boot_identity(&self) -> kr_pairing::platform::BootIdentity {
        let value = kr_ipc::identity::boot_identity()
            .map(|identity| identity.value.as_slice().to_vec())
            .unwrap_or_default();
        kr_pairing::platform::BootIdentity(kr_cbor::sha256(&value))
    }

    fn wall_clock_ms(&self) -> u64 {
        kr_ipc::now_ms().get() + self.ahead()
    }
}

/// The owner's ceremony, as a host that has an enrolled owner signer runs it.
///
/// This is the real acceptance: the challenge is issued and recorded here, the proof is signed by
/// the enrolled key, and the ledger consumes it exactly once. Nothing in these tests asserts a
/// confirmation by writing one down.
struct Ceremony {
    owner: kr_crypto::keys::AuthorisationKeyPair,
    ledger: std::sync::Mutex<kr_pairing::confirm::ConfirmationLedger>,
    clock: Clock,
    device_id: kr_protocol::ids::DeviceId,
    endpoint_id: kr_protocol::scalars::EndpointKey,
    /// A step of a test's own, run once just after this host accepts a confirmation: after the
    /// daemon built what the owner confirmed, and before the change it confirms holds anything.
    after_accept: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl Ceremony {
    fn new() -> Self {
        Self {
            owner: kr_crypto::keys::AuthorisationKeyPair::generate().expect("an owner key"),
            ledger: std::sync::Mutex::new(kr_pairing::confirm::ConfirmationLedger::new()),
            clock: Clock::default(),
            device_id: kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid()),
            endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes([7u8; 32]),
            after_accept: std::sync::Mutex::new(None),
        }
    }

    /// Issues a challenge for one action and signs it, as the owner's device does.
    fn approve(&self, action: SensitiveAction, digest: Digest256) -> OwnerConfirmationProof {
        let request = kr_pairing::confirm::request_confirmation(
            &self.clock,
            action,
            digest,
            None,
            std::collections::BTreeSet::new(),
            self.device_id,
            self.endpoint_id,
        )
        .expect("a challenge");
        self.ledger
            .lock()
            .expect("the ledger")
            .issue(&request, &self.clock);
        kr_pairing::confirm::sign_confirmation(
            &self.owner,
            &request,
            ConfirmationChannel::OwnerDevicePresence,
        )
        .expect("a proof")
    }
}

impl OwnerConfirmations for Ceremony {
    fn accept(
        &self,
        action: SensitiveAction,
        action_digest: Digest256,
        proof: &OwnerConfirmationProof,
    ) -> kr_controller::Result<ConfirmedAction> {
        let accepted = ConfirmedAction::verify(
            &kr_pairing::confirm::ConfirmationExpectation {
                action,
                action_digest,
                host_device_id: self.device_id,
                host_endpoint_id: self.endpoint_id,
                destination_keys: None,
                destination_rights: &kr_protocol::scalars::CanonicalSet::new(),
            },
            &mut self.ledger.lock().expect("the ledger"),
            &self.clock,
            &proof.request,
            proof,
            self.owner.public(),
            kr_pairing::confirm::HostEnrolment::Enrolled,
        );
        let then = self.after_accept.lock().expect("the step").take();
        if let Some(then) = then {
            then();
        }
        accepted
    }

    fn host_device_id(&self) -> kr_protocol::ids::DeviceId {
        self.device_id
    }

    fn clock(&self) -> &dyn kr_pairing::platform::PairingClock {
        &self.clock
    }
}

/// Opens a daemon-hosted catalogue over a copy of the published development generation.
///
/// The generation is copied onto the internal disk before anything opens it, so nothing this test
/// starts reads a path on the workspace volume.
fn host() -> Host {
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let module = CatalogueModule::open(&environment).expect("an openable catalogue");
    let working_temp = tempfile::tempdir().expect("a temporary directory");
    let working = working_temp.path().join("development");
    copy_tree(&fixture(), &working);
    Host {
        _temp: temp,
        module,
        environment_id,
        working,
        _working_temp: working_temp,
        ceremony: Ceremony::new(),
    }
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a destination");
    let mut stack = vec![from.to_path_buf()];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).expect("readable").flatten() {
            let source = entry.path();
            if source.is_dir() {
                stack.push(source);
                continue;
            }
            let relative = source.strip_prefix(from).expect("inside the tree");
            let destination = to.join(relative);
            std::fs::create_dir_all(destination.parent().expect("a parent")).expect("writable");
            std::fs::copy(&source, &destination).expect("copyable");
        }
    }
}

fn directory_url(path: &Path) -> String {
    let absolute = std::fs::canonicalize(path).expect("an existing directory");
    url::Url::from_directory_path(absolute)
        .expect("an absolute path")
        .to_string()
}

fn request<T: serde::Serialize>(method: Method, params: &T) -> Request {
    Request {
        request_id: RequestId::new(1),
        method: MethodName::new(method.as_str()).expect("a registered method"),
        method_version: MethodVersion::V1,
        params: ParamsValue::from_typed(params).expect("serialisable"),
    }
}

fn mutation<T: serde::Serialize>(
    method: Method,
    environment_id: EnvironmentId,
    params: &T,
) -> MutationRequest {
    MutationRequest {
        request_id: RequestId::new(1),
        method: MethodName::new(method.as_str()).expect("a registered method"),
        method_version: MethodVersion::V1,
        action_id: ActionId::new(kr_ipc::new_uuid()),
        grant_id: Nullable::null(),
        target: ActionTarget {
            environment_id,
            session_id: Nullable::null(),
            session_epoch: Nullable::null(),
            application_instance_id: Nullable::null(),
            agent_binding_revision: Nullable::null(),
        },
        expected: ParamsValue::from_typed(&serde_json::json!({})).expect("serialisable"),
        action_window_id: ActionWindowId::new("test-window").expect("a window identifier"),
        requested_ttl_ms: DurationMs::new(30_000),
        params: ParamsValue::from_typed(params).expect("serialisable"),
    }
}

fn ok<T: kr_protocol::wire::WireMessage>(frame: ControlFrame) -> T {
    match frame {
        ControlFrame::Response(response) => match response.outcome {
            Outcome::Ok(value) => value.to_typed().expect("a readable result"),
            Outcome::Error(error) => panic!("refused: {error:?}"),
        },
        other => panic!("not a response: {other:?}"),
    }
}

fn refusal(frame: ControlFrame) -> kr_protocol::error::ProtocolError {
    match frame {
        ControlFrame::Response(response) => match response.outcome {
            Outcome::Error(error) => error,
            Outcome::Ok(value) => panic!("answered instead of refusing: {value:?}"),
        },
        other => panic!("not a response: {other:?}"),
    }
}

fn budgets() -> wire::CatalogueBudgets {
    let defaults = kr_plugin_sdk::limits::RepositoryBudgets::defaults();
    wire::CatalogueBudgets {
        metadata_bytes: defaults.metadata_bytes,
        metadata_entries: defaults.metadata_entries,
        retained_generations: defaults.retained_generations,
        retained_metadata_bytes: defaults.retained_metadata_bytes,
        payload_cache_bytes: defaults.payload_cache_bytes,
        full_offline_mirror: false,
    }
}

fn add_params(host: &Host) -> wire::CatalogueAddParams {
    add_params_for(host, "development", Vec::new())
}

/// The parameters that enrol the development generation as `catalogue_id`, permitting `ceiling`
/// beyond the default, with the owner's confirmation of that enrolment.
fn add_params_for(
    host: &Host,
    catalogue_id: &str,
    ceiling: Vec<String>,
) -> wire::CatalogueAddParams {
    use base64::Engine as _;
    let root = std::fs::read(host.working.join("root.json")).expect("a trust root");
    let metadata_url = directory_url(&host.working.join("metadata"));
    let targets_url = directory_url(&host.working.join("targets"));
    // The owner is asked about this exact enrolment: this repository, this root and this ceiling.
    // The client builds the plan the host will build, which is what makes the digests agree.
    let digest = CatalogueTrustPlan {
        environment_id: host.environment_id,
        catalogue_id: catalogue_id.to_owned(),
        root_digest: kr_plugin_sdk::digest::PayloadDigest::of(&root).to_string(),
        root_key_ids: root_key_ids(&root, &metadata_url, &targets_url),
        ceiling: ceiling.iter().cloned().collect(),
    }
    .action_digest()
    .expect("a digest");
    wire::CatalogueAddParams {
        environment_id: host.environment_id,
        catalogue_id: catalogue_id.to_owned(),
        kind: wire::CatalogueKind::Local,
        metadata_url,
        targets_url,
        root: base64::engine::general_purpose::STANDARD.encode(&root),
        budgets: budgets(),
        ceiling,
        owner_confirmation: host
            .ceremony
            .approve(SensitiveAction::TrustRepositoryRoot, digest),
    }
}

/// The key identifiers the root declares for its own role, read out of the root document.
fn root_key_ids(
    root: &[u8],
    metadata_url: &str,
    targets_url: &str,
) -> kr_protocol::scalars::CanonicalSet<String> {
    Enrolment::new(
        RepositoryId::new("development").expect("a valid identifier"),
        RepositoryKind::Local,
        url::Url::parse(metadata_url).expect("a location"),
        url::Url::parse(targets_url).expect("a location"),
        root.to_vec(),
        kr_plugin_sdk::limits::RepositoryBudgets::defaults(),
        CapabilityCeiling::default_ceiling(),
    )
    .expect("an enrolment")
    .root_key_ids()
    .expect("a readable root")
    .into_iter()
    .collect()
}

/// The parameters of a `plugin.grant`, with the owner's confirmation of that exact grant.
fn grant_params(host: &Host, package_digest: &str, grant: Vec<String>) -> wire::PluginGrantParams {
    let digest = PluginGrantPlan {
        environment_id: host.environment_id,
        plugin_id: plugin(),
        version: "0.1.0".to_owned(),
        package_digest: package_digest.to_owned(),
        grant: grant.iter().cloned().collect(),
    }
    .action_digest()
    .expect("a digest");
    wire::PluginGrantParams {
        environment_id: host.environment_id,
        plugin_id: plugin(),
        package_digest: package_digest.to_owned(),
        grant,
        owner_confirmation: host
            .ceremony
            .approve(SensitiveAction::GrantExecutableCapability, digest),
    }
}

fn plugin() -> PluginId {
    PluginId::new("kalareach/example-declarative").expect("a valid plugin identifier")
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-23.28: the catalogue group
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn kr_req_23_28_the_catalogue_group_adds_syncs_pins_lists_and_removes() {
    let host = host();

    let added: wire::CatalogueAddResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::CatalogueAdd,
                host.environment_id,
                &add_params(&host),
            ),
            Method::CatalogueAdd,
            Some(host.confirmations()),
        )
        .await);
    assert_eq!(added.catalogue.catalogue_id, "development");
    assert_eq!(
        added.catalogue.generation,
        Nullable(None),
        "nothing is synced yet"
    );
    assert_eq!(
        added.catalogue.ceiling.len(),
        3,
        "a new enrolment gets the default ceiling and no more"
    );

    let synced: wire::CatalogueSyncResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::CatalogueSync,
                host.environment_id,
                &wire::CatalogueSyncParams {
                    environment_id: host.environment_id,
                    catalogue_id: "development".to_owned(),
                },
            ),
            Method::CatalogueSync,
            Some(host.confirmations()),
        )
        .await);
    assert_eq!(synced.generation.get(), 1);
    assert_eq!(synced.entries, U64::new(7));
    assert_eq!(synced.mirrored_payloads, U64::new(0));

    let listed: wire::CatalogueListResult = ok(host
        .module
        .read_frame(
            ActorIngress::LocalIpc,
            &request(
                Method::CatalogueList,
                &wire::CatalogueListParams {
                    environment_id: host.environment_id,
                },
            ),
        )
        .await);
    assert_eq!(listed.catalogues.len(), 1);
    let summary = &listed.catalogues[0];
    assert_eq!(
        summary.generation,
        Nullable(Some(RepositoryGeneration::new(1)))
    );
    assert_eq!(summary.entries, U64::new(7));
    assert_eq!(summary.budgets.metadata_bytes.get(), 64 * 1024 * 1024);
    assert_eq!(summary.budgets.metadata_entries.get(), 100_000);
    assert_eq!(summary.budgets.retained_generations.get(), 2);
    assert_eq!(
        summary.budgets.retained_metadata_bytes.get(),
        128 * 1024 * 1024
    );
    assert_eq!(
        summary.budgets.payload_cache_bytes.get(),
        1024 * 1024 * 1024
    );
    assert!(!summary.budgets.full_offline_mirror);
    assert_eq!(
        summary.root_digest.len(),
        64,
        "the adopted root is named by its digest"
    );

    let pinned: wire::CataloguePinResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::CataloguePin,
                host.environment_id,
                &wire::CataloguePinParams {
                    environment_id: host.environment_id,
                    catalogue_id: "development".to_owned(),
                    generation: Nullable(Some(RepositoryGeneration::new(1))),
                },
            ),
            Method::CataloguePin,
            Some(host.confirmations()),
        )
        .await);
    assert_eq!(
        pinned.catalogue.pinned_generation,
        Nullable(Some(RepositoryGeneration::new(1)))
    );

    // A pin that names a generation this host is not on is refused.
    let refused = refusal(
        host.module
            .write_frame_admitted(
                &mutation(
                    Method::CataloguePin,
                    host.environment_id,
                    &wire::CataloguePinParams {
                        environment_id: host.environment_id,
                        catalogue_id: "development".to_owned(),
                        generation: Nullable(Some(RepositoryGeneration::new(9))),
                    },
                ),
                Method::CataloguePin,
                Some(host.confirmations()),
            )
            .await,
    );
    assert_eq!(refused.code, ErrorCode::InvalidArgument);

    let removed: wire::CatalogueRemoveResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::CatalogueRemove,
                host.environment_id,
                &wire::CatalogueRemoveParams {
                    environment_id: host.environment_id,
                    catalogue_id: "development".to_owned(),
                },
            ),
            Method::CatalogueRemove,
            Some(host.confirmations()),
        )
        .await);
    assert_eq!(removed.catalogue_id, "development");
    assert!(removed.installed_packages.is_empty());
}

#[tokio::test]
async fn kr_req_23_28_a_second_enrolment_of_one_root_is_refused() {
    let host = host();
    let params = add_params(&host);
    let _: wire::CatalogueAddResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(Method::CatalogueAdd, host.environment_id, &params),
            Method::CatalogueAdd,
            Some(host.confirmations()),
        )
        .await);
    let params2 = add_params(&host);
    let refused = refusal(
        host.module
            .write_frame_admitted(
                &mutation(Method::CatalogueAdd, host.environment_id, &params2),
                Method::CatalogueAdd,
                Some(host.confirmations()),
            )
            .await,
    );
    assert_eq!(refused.code, ErrorCode::InvalidArgument);
    assert!(refused.message.contains("already enrolled"), "{refused:?}");
}

#[tokio::test]
async fn a_request_for_another_environment_is_refused_before_anything_is_read() {
    let host = host();
    let other = EnvironmentId::new(kr_ipc::new_uuid());
    let refused = refusal(
        host.module
            .read_frame(
                ActorIngress::LocalIpc,
                &request(
                    Method::CatalogueList,
                    &wire::CatalogueListParams {
                        environment_id: other,
                    },
                ),
            )
            .await,
    );
    assert_eq!(refused.code, ErrorCode::InvalidArgument);
    assert!(refused.message.contains("owns environment"), "{refused:?}");
}

#[tokio::test]
async fn a_location_that_is_a_version_control_branch_is_refused() {
    let host = host();
    let mut params = add_params(&host);
    params.metadata_url = "git+https://example.invalid/plugins.git".to_owned();
    let refused = refusal(
        host.module
            .write_frame_admitted(
                &mutation(Method::CatalogueAdd, host.environment_id, &params),
                Method::CatalogueAdd,
                Some(host.confirmations()),
            )
            .await,
    );
    assert_eq!(refused.code, ErrorCode::RepositoryUntrusted);
    assert!(
        refused.message.contains("never update authority"),
        "{refused:?}"
    );
}

/// A catalogue whose budgets would keep no generation at all is refused at enrolment: a repository
/// keeps at least the generation it is on.
#[tokio::test]
async fn a_catalogue_that_would_keep_no_generation_is_refused() {
    let host = host();
    let mut params = add_params(&host);
    params.budgets.retained_generations = U64::new(0);
    let refused = refusal(
        host.module
            .write_frame_admitted(
                &mutation(Method::CatalogueAdd, host.environment_id, &params),
                Method::CatalogueAdd,
                Some(host.confirmations()),
            )
            .await,
    );
    assert_eq!(refused.code, ErrorCode::InvalidArgument);
    assert!(
        refused.message.contains("at least one generation"),
        "{refused:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-23.29: the plugin group
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn kr_req_23_29_the_plugin_group_installs_enables_pins_reads_and_removes() {
    let host = host();
    let _: wire::CatalogueAddResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::CatalogueAdd,
                host.environment_id,
                &add_params(&host),
            ),
            Method::CatalogueAdd,
            Some(host.confirmations()),
        )
        .await);
    let _: wire::CatalogueSyncResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::CatalogueSync,
                host.environment_id,
                &wire::CatalogueSyncParams {
                    environment_id: host.environment_id,
                    catalogue_id: "development".to_owned(),
                },
            ),
            Method::CatalogueSync,
            Some(host.confirmations()),
        )
        .await);

    let digest = {
        let catalogue = host.module.catalogue().lock().await;
        let id = kr_plugin_catalogue::RepositoryId::new("development").expect("a valid identifier");
        let index = catalogue.index(&id).expect("an activated index");
        index
            .find(
                &plugin(),
                &kr_plugin_sdk::version::PackageVersion::parse("0.1.0").expect("a version"),
            )
            .expect("the example package")
            .manifest_digest
            .to_string()
    };

    // A hash the caller did not read is refused: pinning and rollback are on immutable hashes.
    let wrong = refusal(
        host.module
            .write_frame_admitted(
                &mutation(
                    Method::PluginInstall,
                    host.environment_id,
                    &wire::PluginInstallParams {
                        environment_id: host.environment_id,
                        catalogue_id: "development".to_owned(),
                        plugin_id: plugin(),
                        version: "0.1.0".to_owned(),
                        package_digest: "0".repeat(64),
                        grant: Vec::new(),
                        owner_confirmation: Nullable::null(),
                    },
                ),
                Method::PluginInstall,
                Some(host.confirmations()),
            )
            .await,
    );
    assert_eq!(wrong.code, ErrorCode::AttachmentIntegrity);

    let unconfirmed = refusal(
        host.module
            .write_frame_admitted(
                &mutation(
                    Method::PluginInstall,
                    host.environment_id,
                    &wire::PluginInstallParams {
                        environment_id: host.environment_id,
                        catalogue_id: "development".to_owned(),
                        plugin_id: plugin(),
                        version: "0.1.0".to_owned(),
                        package_digest: digest.clone(),
                        grant: vec!["native_bridge.install".to_owned()],
                        owner_confirmation: Nullable::null(),
                    },
                ),
                Method::PluginInstall,
                Some(host.confirmations()),
            )
            .await,
    );
    // Installing carries no owner confirmation, so no installation grants a native bridge, and
    // this package does not ask for one either.
    assert_eq!(
        unconfirmed.code,
        ErrorCode::PluginGrantRequired,
        "{unconfirmed:?}"
    );

    let installed: wire::PluginInstallResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::PluginInstall,
                host.environment_id,
                &wire::PluginInstallParams {
                    environment_id: host.environment_id,
                    catalogue_id: "development".to_owned(),
                    plugin_id: plugin(),
                    version: "0.1.0".to_owned(),
                    package_digest: digest.clone(),
                    grant: Vec::new(),
                    owner_confirmation: Nullable::null(),
                },
            ),
            Method::PluginInstall,
            Some(host.confirmations()),
        )
        .await);
    assert_eq!(installed.plugin.package_digest, digest);
    assert!(!installed.plugin.enabled, "installing does not enable");
    assert!(!installed.plugin.revoked);
    assert!(
        installed.capabilities.iter().all(|grant| grant.permitted),
        "the example package is inside the default ceiling"
    );

    let enabled: wire::PluginEnableResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::PluginEnable,
                host.environment_id,
                &wire::PluginEnableParams {
                    environment_id: host.environment_id,
                    plugin_id: plugin(),
                },
            ),
            Method::PluginEnable,
            Some(host.confirmations()),
        )
        .await);
    assert!(enabled.plugin.enabled);

    let pinned: wire::PluginPinResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::PluginPin,
                host.environment_id,
                &wire::PluginPinParams {
                    environment_id: host.environment_id,
                    plugin_id: plugin(),
                    package_digest: Nullable(Some(digest.clone())),
                },
            ),
            Method::PluginPin,
            Some(host.confirmations()),
        )
        .await);
    assert!(pinned.plugin.pinned);

    let listed: wire::PluginListResult = ok(host
        .module
        .read_frame(
            ActorIngress::LocalIpc,
            &request(
                Method::PluginList,
                &wire::PluginListParams {
                    environment_id: host.environment_id,
                },
            ),
        )
        .await);
    assert_eq!(listed.plugins.len(), 1);
    assert_eq!(listed.plugins[0].catalogue_id, "development");
    assert_eq!(listed.plugins[0].live_bindings, U64::new(0));

    let capabilities: wire::PluginCapabilitiesResult = ok(host
        .module
        .read_frame(
            ActorIngress::LocalIpc,
            &request(
                Method::PluginCapabilities,
                &wire::PluginCapabilitiesParams {
                    environment_id: host.environment_id,
                    plugin_id: plugin(),
                },
            ),
        )
        .await);
    assert_eq!(capabilities.plugin.package_digest, digest);
    assert!(!capabilities.capabilities.is_empty());
    assert_eq!(
        capabilities.capabilities.len(),
        capabilities.evidence.len(),
        "every requested capability has an answer"
    );
    for record in &capabilities.evidence {
        assert_eq!(
            record.package_digest, digest,
            "evidence names the exact package hash it is about"
        );
        assert_ne!(
            record.state,
            wire::PluginCapabilityState::QualifiedAvailable,
            "nothing on this host has probed anything"
        );
        assert!(
            record.disabled_reason.0.is_some(),
            "an unusable state carries a reason a person reads"
        );
        assert!(!record.invalidated_by.is_empty());
    }

    // A capability the repository's ceiling does not reach is refused, by name.
    let refused = refusal(
        host.module
            .write_frame_admitted(
                &mutation(
                    Method::PluginGrant,
                    host.environment_id,
                    &grant_params(
                        &host,
                        &installed.plugin.package_digest,
                        vec!["filesystem.write".to_owned()],
                    ),
                ),
                Method::PluginGrant,
                Some(host.confirmations()),
            )
            .await,
    );
    assert_eq!(refused.code, ErrorCode::InvalidArgument);
    assert!(refused.message.contains("filesystem.write"), "{refused:?}");

    let disabled: wire::PluginEnableResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::PluginDisable,
                host.environment_id,
                &wire::PluginEnableParams {
                    environment_id: host.environment_id,
                    plugin_id: plugin(),
                },
            ),
            Method::PluginDisable,
            Some(host.confirmations()),
        )
        .await);
    assert!(!disabled.plugin.enabled);

    let removed: wire::PluginRemoveResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::PluginRemove,
                host.environment_id,
                &wire::PluginRemoveParams {
                    environment_id: host.environment_id,
                    plugin_id: plugin(),
                },
            ),
            Method::PluginRemove,
            Some(host.confirmations()),
        )
        .await);
    assert_eq!(removed.plugin_id, plugin());
    assert_eq!(removed.closed_bindings, U64::new(0));
}

#[tokio::test]
async fn kr_req_23_29_removing_a_catalogue_does_not_uninstall_what_came_from_it() {
    let host = host();
    let _: wire::CatalogueAddResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::CatalogueAdd,
                host.environment_id,
                &add_params(&host),
            ),
            Method::CatalogueAdd,
            Some(host.confirmations()),
        )
        .await);
    let _: wire::CatalogueSyncResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::CatalogueSync,
                host.environment_id,
                &wire::CatalogueSyncParams {
                    environment_id: host.environment_id,
                    catalogue_id: "development".to_owned(),
                },
            ),
            Method::CatalogueSync,
            Some(host.confirmations()),
        )
        .await);
    let digest = {
        let catalogue = host.module.catalogue().lock().await;
        let id = kr_plugin_catalogue::RepositoryId::new("development").expect("a valid identifier");
        catalogue
            .index(&id)
            .expect("activated")
            .find(
                &plugin(),
                &kr_plugin_sdk::version::PackageVersion::parse("0.1.0").expect("a version"),
            )
            .expect("the example package")
            .manifest_digest
            .to_string()
    };
    let _: wire::PluginInstallResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::PluginInstall,
                host.environment_id,
                &wire::PluginInstallParams {
                    environment_id: host.environment_id,
                    catalogue_id: "development".to_owned(),
                    plugin_id: plugin(),
                    version: "0.1.0".to_owned(),
                    package_digest: digest,
                    grant: Vec::new(),
                    owner_confirmation: Nullable::null(),
                },
            ),
            Method::PluginInstall,
            Some(host.confirmations()),
        )
        .await);

    let removed: wire::CatalogueRemoveResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::CatalogueRemove,
                host.environment_id,
                &wire::CatalogueRemoveParams {
                    environment_id: host.environment_id,
                    catalogue_id: "development".to_owned(),
                },
            ),
            Method::CatalogueRemove,
            Some(host.confirmations()),
        )
        .await);
    assert_eq!(removed.installed_packages, vec![plugin()]);

    let listed: wire::PluginListResult = ok(host
        .module
        .read_frame(
            ActorIngress::LocalIpc,
            &request(
                Method::PluginList,
                &wire::PluginListParams {
                    environment_id: host.environment_id,
                },
            ),
        )
        .await);
    assert_eq!(
        listed.plugins.len(),
        1,
        "the package is still installed, on the hash it was installed at"
    );
}

// ---------------------------------------------------------------------------------------------
// Through the daemon's own endpoint
// ---------------------------------------------------------------------------------------------

/// A supervisor that starts nothing. No worker is needed to enrol a catalogue.
#[derive(Debug)]
struct NoWorkers;

impl kr_controller::supervision::WorkerSupervisor for NoWorkers {
    fn start(
        &self,
        _launch: &kr_controller::supervision::WorkerLaunch,
    ) -> kr_controller::supervision::LaunchOutcome {
        kr_controller::supervision::LaunchOutcome::NotStarted {
            detail: "this test starts no workers".to_owned(),
        }
    }

    fn describe(&self) -> &'static str {
        "a supervisor that starts nothing"
    }
}

/// Both groups reach the catalogue through the daemon's own admission, not only through the
/// module. A method the envelope check does not know about is refused before it is dispatched, and
/// nothing that drives the module directly would notice.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_groups_reach_the_catalogue_through_the_daemon() {
    use kr_crypto::store::{StoreSelection, open_store_in};
    use kr_protocol::local::LocalClientKind;

    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let environment_id = temp.environment_id();
    let secrets = environment.secrets_dir();
    let build = kr_protocol::ids::BuildId::new("kr-test/0").expect("a build identifier");
    let controller =
        kr_controller::service::Controller::start(kr_controller::service::ControllerSetup {
            paths: environment.clone(),
            environment_id,
            terminal: Box::new(kr_controller::supervision::NoTerminal),
            identity: Box::new(move || {
                let store = open_store_in(&secrets).expect("a secret store");
                Ok(kr_ipc::verify::ControllerIdentity::open(
                    store.store.as_ref(),
                    environment_id,
                    false,
                )
                .expect("an identity"))
            }),
            secret_store: StoreSelection::File,
            boot_identity: kr_ipc::identity::boot_identity().expect("a boot identity"),
            supervisor: Box::new(NoWorkers),
            worker_program: std::path::PathBuf::from("/nonexistent/kr-worker"),
            build_id: build.clone(),
            release: "0".to_owned(),
            shell_packages: None,
        })
        .await
        .expect("the daemon starts");
    let endpoint = environment.controller_endpoint().expect("an endpoint");
    let listener = kr_ipc::endpoint::Listener::bind(&endpoint).expect("binds the endpoint");
    tokio::spawn(std::sync::Arc::clone(&controller).serve_clients(listener));

    let mut client = kr_ipc::client::LocalClient::connect(&endpoint, LocalClientKind::Cli, build)
        .await
        .expect("connects");

    // A read reaches the module and answers.
    let listed: wire::CatalogueListResult = client
        .request(
            Method::CatalogueList,
            &wire::CatalogueListParams { environment_id },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("and is answered")
        .to_typed()
        .expect("a readable result");
    assert!(listed.catalogues.is_empty());

    // And so does a mutation: what this proves is that the envelope check admits it, which is the
    // one thing driving the module directly cannot show. The catalogue itself answers, naming the
    // repository nobody enrolled rather than the method nobody serves.
    let target = ActionTarget {
        environment_id,
        session_id: Nullable::null(),
        session_epoch: Nullable::null(),
        application_instance_id: Nullable::null(),
        agent_binding_revision: Nullable::null(),
    };
    let sync = client
        .compose(
            Method::CatalogueSync,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &wire::CatalogueSyncParams {
                environment_id,
                catalogue_id: "development".to_owned(),
            },
        )
        .await
        .expect("a mutation this client can send");
    let submitted_at = kr_ipc::now_ms().get();
    let refused = client
        .repeat(&sync)
        .await
        .expect("the call reaches the daemon")
        .expect_err("nothing is enrolled yet");
    assert_eq!(refused.code, ErrorCode::ResourceUnavailable, "{refused:?}");

    // The receipt keeps the deadline the daemon accepted the action under: the earliest of the
    // window and the requested lifetime, and never nothing. A resubmission is answered from the
    // receipt and moves nothing in it.
    let first = read_receipt(&mut client, sync.action_id).await;
    let deadline = first
        .receipt
        .accepted_deadline_ms
        .0
        .expect("the deadline the action was accepted under")
        .get();
    assert!(
        deadline > submitted_at
            && deadline <= kr_ipc::now_ms().get() + kr_protocol::limits::DEFAULT_MUTATION_TTL.get(),
        "{deadline} is inside the lifetime asked for at {submitted_at}"
    );
    let again = client
        .repeat(&sync)
        .await
        .expect("the call reaches the daemon")
        .expect_err("answered from the receipt");
    assert_eq!(again, refused);
    assert_eq!(
        read_receipt(&mut client, sync.action_id).await.receipt,
        first.receipt,
        "a resubmission changes nothing in the receipt"
    );

    // `catalogue.add` reaches the module too, and stops at the owner's ceremony. This daemon has
    // no enrolled owner signer, and section 10 does not let the caller's operating-system identity
    // stand in for one.
    let working_temp = tempfile::tempdir().expect("a temporary directory");
    let working = working_temp.path().join("development");
    copy_tree(&fixture(), &working);
    let ceremony = Ceremony::new();
    let params = {
        use base64::Engine as _;
        let root = std::fs::read(working.join("root.json")).expect("a trust root");
        wire::CatalogueAddParams {
            environment_id,
            catalogue_id: "development".to_owned(),
            kind: wire::CatalogueKind::Local,
            metadata_url: directory_url(&working.join("metadata")),
            targets_url: directory_url(&working.join("targets")),
            root: base64::engine::general_purpose::STANDARD.encode(&root),
            budgets: budgets(),
            ceiling: Vec::new(),
            owner_confirmation: ceremony.approve(
                SensitiveAction::TrustRepositoryRoot,
                Digest256::from_bytes([0u8; 32]),
            ),
        }
    };
    let refused = client
        .mutate(
            Method::CatalogueAdd,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &params,
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("this host has no owner to confirm with");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        refused.message.contains("owner"),
        "the refusal names the ceremony: {refused:?}"
    );

    let listed: wire::PluginListResult = client
        .request(
            Method::PluginList,
            &wire::PluginListParams { environment_id },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("and is answered")
        .to_typed()
        .expect("a readable result");
    assert!(listed.plugins.is_empty());

    // What a restarted daemon opens reads the same receipt: the deadline is recorded with the
    // claim, not derived again from whatever admits the next request.
    let reopened = CatalogueModule::open(&environment).expect("the catalogue reopens");
    let restarted = reopened
        .action_read(&first.receipt.actor_id, sync.action_id)
        .await
        .expect("readable")
        .expect("the receipt survives");
    assert_eq!(restarted.receipt, first.receipt);
}

/// Reads one action's receipt through `action.read`.
async fn read_receipt(
    client: &mut kr_ipc::client::LocalClient,
    action_id: ActionId,
) -> kr_protocol::receipt::ActionReadResult {
    client
        .request(
            Method::ActionRead,
            &kr_protocol::receipt::ActionReadParams {
                action_id,
                session_id: None,
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect("and is answered")
        .to_typed()
        .expect("a readable receipt")
}

/// An admission refusal reaches the caller as the class the daemon decided.
///
/// A withdrawn registration and a storage failure are different answers, and the adapter between
/// the daemon's admission and the catalogue's own vocabulary must not flatten them: somebody told
/// to ask for authority when the disk is what failed will do the wrong thing about it.
#[tokio::test]
async fn an_admission_refusal_keeps_the_class_the_daemon_decided() {
    let host = host();
    let actor = ActorId::new("kr:actor:test").expect("a valid actor");

    // The catalogue has to be enrolled, so the refusal comes from the admission inside the
    // effect rather than from the repository being absent.
    let _: wire::CatalogueAddResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::CatalogueAdd,
                host.environment_id,
                &add_params(&host),
            ),
            Method::CatalogueAdd,
            Some(host.confirmations()),
        )
        .await);

    for code in [ErrorCode::StorageUnavailable, ErrorCode::PermissionDenied] {
        // Every early check admits the action. The refusal is the daemon's answer at the
        // commit, inside the runtime, after the catalogue's lock and the repository's, which is
        // where the adapter between the daemon's vocabulary and the catalogue's own sits.
        let admission = Arc::new(RefusedAtCommit::new(code));
        let mutation = mutation(
            Method::CatalogueSync,
            host.environment_id,
            &wire::CatalogueSyncParams {
                environment_id: host.environment_id,
                catalogue_id: "development".to_owned(),
            },
        );
        let refused = refusal(
            host.module
                .write_frame(
                    &actor,
                    &mutation,
                    Method::CatalogueSync,
                    Some(host.confirmations()),
                    admission.clone(),
                )
                .await,
        );
        assert!(
            admission.commits.load(std::sync::atomic::Ordering::SeqCst) > 0,
            "the refusal came from the commit inside the catalogue"
        );
        assert_eq!(refused.code, code, "{refused:?}");
        assert!(
            refused.message.contains("the daemon's own answer"),
            "the refusal carries what the daemon said: {refused:?}"
        );

        // The receipt says the same thing to a resubmission, and says it was refused rather than
        // unknown: nothing was committed.
        let retained = refusal(
            host.module
                .retained(&actor, &mutation, Method::CatalogueSync)
                .await
                .expect("a receipt"),
        );
        assert_eq!(retained, refused);
        let read = host
            .module
            .action_read(&actor, mutation.action_id)
            .await
            .expect("readable")
            .expect("a receipt");
        assert_eq!(
            read.receipt.state,
            kr_protocol::receipt::ReceiptState::Refused
        );
    }
}

/// An admission whose early checks pass and whose commit refuses, with the daemon's own code.
struct RefusedAtCommit {
    code: ErrorCode,
    commits: std::sync::atomic::AtomicUsize,
}

impl RefusedAtCommit {
    fn new(code: ErrorCode) -> Self {
        Self {
            code,
            commits: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

impl Authority for RefusedAtCommit {
    fn check(&self) -> CatalogueResult<()> {
        Ok(())
    }

    fn commit(
        &self,
        _effect: &Effect,
        _commit: &mut dyn FnMut() -> CatalogueResult<()>,
    ) -> CatalogueResult<()> {
        self.commits
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Err(CatalogueError::Refused(
            kr_protocol::error::ProtocolError::new(self.code, "the daemon's own answer"),
        ))
    }

    fn owner_confirmed(&self) -> bool {
        false
    }
}

impl Admission for RefusedAtCommit {
    fn accepted_deadline_ms(&self) -> Option<u64> {
        None
    }
}

/// An admission whose first check already fails, as a lapsed window does.
struct Lapsed;

impl Admission for Lapsed {
    fn accepted_deadline_ms(&self) -> Option<u64> {
        None
    }
}

impl Authority for Lapsed {
    fn check(&self) -> CatalogueResult<()> {
        Err(CatalogueError::Refused(
            kr_protocol::error::ProtocolError::new(ErrorCode::PermissionDenied, "window expired"),
        ))
    }

    fn commit(
        &self,
        _effect: &Effect,
        _commit: &mut dyn FnMut() -> CatalogueResult<()>,
    ) -> CatalogueResult<()> {
        self.check()
    }

    fn owner_confirmed(&self) -> bool {
        false
    }
}

#[test]
fn a_catalogue_mutation_names_an_environment_and_never_a_session() {
    let environment_id = EnvironmentId::new(kr_ipc::new_uuid());
    let params = wire::CatalogueSyncParams {
        environment_id,
        catalogue_id: "development".to_owned(),
    };
    let mut named = mutation(Method::CatalogueSync, environment_id, &params);
    assert!(CatalogueModule::check_subject(Method::CatalogueSync, &named).is_ok());

    // A target that names a session is a receipt against something the effect never touched.
    named.target.session_id = Nullable(Some(kr_protocol::ids::SessionId::new(kr_ipc::new_uuid())));
    assert!(CatalogueModule::check_subject(Method::CatalogueSync, &named).is_err());

    // And the envelope and the parameters have to name one environment.
    let elsewhere = mutation(
        Method::CatalogueSync,
        EnvironmentId::new(kr_ipc::new_uuid()),
        &params,
    );
    assert!(CatalogueModule::check_subject(Method::CatalogueSync, &elsewhere).is_err());
}

// ---------------------------------------------------------------------------------------------
// The generated authority table
// ---------------------------------------------------------------------------------------------

#[test]
fn kr_req_23_28_and_23_29_every_method_has_one_exhaustive_authority_entry() {
    use kr_protocol::actor::ActorIngress;
    use kr_protocol::authority::{
        AuthorityDecision, ConfirmationRequirement, EffectClass, RequiredAuthority,
    };
    use kr_protocol::method::{MethodGroup, decide};
    use kr_protocol::rights::ActionRight;

    let mut seen = 0usize;
    for entry in kr_protocol::method::REGISTRY {
        if !matches!(
            entry.group,
            MethodGroup::PluginCatalogues | MethodGroup::Plugins
        ) {
            continue;
        }
        seen += 1;
        assert!(
            CatalogueModule::serves(entry.method),
            "{} is in the group and the daemon does not serve it",
            entry.name
        );
        let AuthorityDecision::Listed(listed) =
            decide(entry.name, MethodVersion::V1, ActorIngress::LocalIpc)
        else {
            panic!("{} is not listed", entry.name);
        };
        assert_eq!(listed.name, entry.name);
        assert!(
            !listed.resource_selectors.is_empty(),
            "{} names no resource selector",
            entry.name
        );
        if listed.effect == EffectClass::Write {
            assert!(
                listed.required_rights.iter().any(|required| matches!(
                    required.authority,
                    RequiredAuthority::Right {
                        right: ActionRight::HostManage
                    }
                )),
                "{} changes something without host.manage",
                entry.name
            );
        }
    }
    assert_eq!(seen, 13, "five catalogue methods and eight plugin methods");

    // A new trust root always needs the owner; a sync needs one only when it would enlarge.
    let add = kr_protocol::method::REGISTRY
        .iter()
        .find(|entry| entry.name == "catalogue.add")
        .expect("registered");
    assert_eq!(add.confirmation, ConfirmationRequirement::Always);
    let sync = kr_protocol::method::REGISTRY
        .iter()
        .find(|entry| entry.name == "catalogue.sync")
        .expect("registered");
    assert_eq!(
        sync.confirmation,
        ConfirmationRequirement::WhenEnlargingAuthority
    );
    let grant = kr_protocol::method::REGISTRY
        .iter()
        .find(|entry| entry.name == "plugin.grant")
        .expect("registered");
    assert_eq!(grant.confirmation, ConfirmationRequirement::Always);
}

#[tokio::test]
async fn catalogue_mutations_are_retained_and_prevent_duplicate_execution() {
    let host = host();
    let actor = ActorId::new("kr:actor:test").expect("valid actor");
    let action_id = ActionId::new(kr_ipc::new_uuid());

    let params = add_params(&host);
    let mut req = mutation(Method::CatalogueAdd, host.environment_id, &params);
    req.action_id = action_id;

    // First execution succeeds.
    let outcome1 = host
        .module
        .write_frame(
            &actor,
            &req,
            Method::CatalogueAdd,
            Some(host.confirmations()),
            Arc::new(Owner::acting()),
        )
        .await;
    let added1: wire::CatalogueAddResult = ok(outcome1);
    assert_eq!(added1.catalogue.catalogue_id, "development");

    // Repeating the same mutation with the same action_id returns the retained result.
    let outcome2 = host
        .module
        .write_frame(
            &actor,
            &req,
            Method::CatalogueAdd,
            Some(host.confirmations()),
            Arc::new(Owner::acting()),
        )
        .await;
    let added2: wire::CatalogueAddResult = ok(outcome2);
    assert_eq!(added2.catalogue.catalogue_id, "development");

    // The receipt belongs to the actor that submitted the action. Owning the identifier is not
    // authority: another actor asking about the same action is told nothing.
    let read = host
        .module
        .action_read(&actor, action_id)
        .await
        .expect("readable")
        .expect("the actor's own receipt");
    assert_eq!(
        read.receipt.state,
        kr_protocol::receipt::ReceiptState::Applied
    );
    let other = ActorId::new("kr:actor:other").expect("valid actor");
    assert!(
        host.module
            .action_read(&other, action_id)
            .await
            .expect("readable")
            .is_none(),
        "another actor's action is not disclosed"
    );

    // Retained lookup via module.retained(...) returns the frame directly.
    let retained = host
        .module
        .retained(&actor, &req, Method::CatalogueAdd)
        .await
        .expect("retained frame exists");
    let added3: wire::CatalogueAddResult = ok(retained);
    assert_eq!(added3.catalogue.catalogue_id, "development");

    // Reusing the same action_id with different parameters produces IdConflict.
    let mut different_params = params.clone();
    different_params.catalogue_id = "other".to_owned();
    let mut conflicting_req =
        mutation(Method::CatalogueAdd, host.environment_id, &different_params);
    conflicting_req.action_id = action_id;

    let conflict = refusal(
        host.module
            .write_frame(
                &actor,
                &conflicting_req,
                Method::CatalogueAdd,
                Some(host.confirmations()),
                Arc::new(Owner::acting()),
            )
            .await,
    );
    assert_eq!(conflict.code, ErrorCode::IdConflict);

    // Admission failure refuses the mutation before any effect occurs.
    let fresh_action = ActionId::new(kr_ipc::new_uuid());
    let mut req_expired = mutation(
        Method::CataloguePin,
        host.environment_id,
        &wire::CataloguePinParams {
            environment_id: host.environment_id,
            catalogue_id: "development".to_owned(),
            generation: Nullable(Some(RepositoryGeneration::new(1))),
        },
    );
    req_expired.action_id = fresh_action;

    let expired = refusal(
        host.module
            .write_frame(
                &actor,
                &req_expired,
                Method::CataloguePin,
                None,
                Arc::new(Lapsed),
            )
            .await,
    );
    assert_eq!(expired.code, ErrorCode::PermissionDenied);
}

// ---------------------------------------------------------------------------------------------
// A disk error is a disk error in every answer
// ---------------------------------------------------------------------------------------------

/// Enrols and synchronises the development catalogue, installs its example package, and returns
/// the package hash.
async fn installed(host: &Host) -> String {
    let digest = synchronised(host).await;
    let _: wire::PluginInstallResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::PluginInstall,
                host.environment_id,
                &install_params(host, &digest),
            ),
            Method::PluginInstall,
            Some(host.confirmations()),
        )
        .await);
    digest
}

/// The parameters that install the example package at `digest`, with no grant.
fn install_params(host: &Host, digest: &str) -> wire::PluginInstallParams {
    wire::PluginInstallParams {
        environment_id: host.environment_id,
        catalogue_id: "development".to_owned(),
        plugin_id: plugin(),
        version: "0.1.0".to_owned(),
        package_digest: digest.to_owned(),
        grant: Vec::new(),
        owner_confirmation: Nullable::null(),
    }
}

/// The installation of the example package at `digest` from `catalogue_id` that a client asks the
/// owner to confirm, with the repository's ceiling as `catalogue.list` reports it.
fn install_plan(
    host: &Host,
    catalogue_id: &str,
    ceiling: &[String],
    digest: &str,
    grant: &[&str],
) -> PluginInstallPlan {
    PluginInstallPlan {
        environment_id: host.environment_id,
        catalogue_id: catalogue_id.to_owned(),
        ceiling: ceiling.iter().cloned().collect(),
        plugin_id: plugin(),
        version: "0.1.0".to_owned(),
        package_digest: digest.to_owned(),
        grant: grant.iter().map(|name| (*name).to_owned()).collect(),
    }
}

/// The parameters that install the example package at `digest` from `catalogue_id`, granting
/// nothing, with the owner's confirmation of the installation `plan` describes, which is what the
/// owner was shown and need not be this request.
fn confirmed_install(
    host: &Host,
    catalogue_id: &str,
    digest: &str,
    plan: &PluginInstallPlan,
) -> wire::PluginInstallParams {
    wire::PluginInstallParams {
        catalogue_id: catalogue_id.to_owned(),
        owner_confirmation: Nullable::some(host.ceremony.approve(
            SensitiveAction::GrantExecutableCapability,
            plan.action_digest().expect("a digest"),
        )),
        ..install_params(host, digest)
    }
}

/// The ceiling `catalogue.list` reports for `catalogue_id`.
async fn listed_ceiling(host: &Host, catalogue_id: &str) -> Vec<String> {
    let listed: wire::CatalogueListResult = ok(host
        .module
        .read_frame(
            ActorIngress::LocalIpc,
            &request(
                Method::CatalogueList,
                &wire::CatalogueListParams {
                    environment_id: host.environment_id,
                },
            ),
        )
        .await);
    listed
        .catalogues
        .into_iter()
        .find(|catalogue| catalogue.catalogue_id == catalogue_id)
        .expect("listed")
        .ceiling
}

/// Rewrites the installed record so the release it names asked only to match metadata, as an
/// installed release that asked for less would have. No package the development generation
/// publishes asks for more than the three passive capabilities, so this is how an installation of
/// one of them comes to widen what it may do.
async fn narrow_installed_request(host: &Host) {
    let connection =
        rusqlite::Connection::open(database_of(host).await).expect("the catalogue's database");
    let requested: String = connection
        .query_row("SELECT requested FROM installations", [], |row| row.get(0))
        .expect("one installation");
    let mut requests: Vec<serde_json::Value> =
        serde_json::from_str(&requested).expect("a list of requests");
    requests.retain(|request| request["capability"] == "metadata.match");
    assert_eq!(requests.len(), 1, "{requested}");
    connection
        .execute(
            "UPDATE installations SET requested = ?1",
            [serde_json::Value::Array(requests).to_string()],
        )
        .expect("rewritten");
}

/// How many capabilities the installed record says its release asked for.
async fn installed_requests(host: &Host) -> usize {
    host.module
        .catalogue()
        .lock()
        .await
        .installation(host.environment_id, &plugin())
        .expect("readable")
        .expect("installed")
        .requested
        .len()
}

/// An installation that may do more than the installation it replaces carries the owner's
/// confirmation of that exact installation, accepted through the ceremony `plugin.grant` uses and
/// consumed once: without one it is refused, one for another package hash or another grant is
/// refused, its own installs, and spending it a second time is refused. None of the refusals
/// changes the installation.
#[tokio::test]
async fn kr_req_10_05_and_11_11_an_installation_that_widens_is_the_owners_confirmed_decision() {
    let host = host();
    let digest = installed(&host).await;
    narrow_installed_request(&host).await;
    let ceiling = listed_ceiling(&host, "development").await;
    let install = |params: wire::PluginInstallParams| {
        let host = &host;
        async move {
            host.module
                .write_frame_admitted(
                    &mutation(Method::PluginInstall, host.environment_id, &params),
                    Method::PluginInstall,
                    Some(host.confirmations()),
                )
                .await
        }
    };

    let refused = refusal(install(install_params(&host, &digest)).await);
    assert_eq!(
        refused.code,
        ErrorCode::OwnerConfirmationRequired,
        "{refused:?}"
    );
    for (what, plan) in [
        (
            "another package hash",
            install_plan(&host, "development", &ceiling, &"0".repeat(64), &[]),
        ),
        (
            "another grant",
            install_plan(
                &host,
                "development",
                &ceiling,
                &digest,
                &["broker.semantic_events"],
            ),
        ),
    ] {
        let refused =
            refusal(install(confirmed_install(&host, "development", &digest, &plan)).await);
        assert_eq!(
            refused.code,
            ErrorCode::PermissionDenied,
            "{what}: {refused:?}"
        );
    }
    assert_eq!(installed_requests(&host).await, 1, "nothing was installed");

    let confirmed = confirmed_install(
        &host,
        "development",
        &digest,
        &install_plan(&host, "development", &ceiling, &digest, &[]),
    );
    let installed: wire::PluginInstallResult = ok(install(confirmed.clone()).await);
    assert_eq!(installed.plugin.package_digest, digest);
    assert_eq!(installed_requests(&host).await, 3, "the release as it asks");

    narrow_installed_request(&host).await;
    let refused = refusal(install(confirmed).await);
    assert_eq!(
        refused.code,
        ErrorCode::PermissionDenied,
        "a confirmation spent once: {refused:?}"
    );
    assert_eq!(installed_requests(&host).await, 1, "nothing was installed");
}

/// A confirmation shown for an installation from one repository does not install the same package
/// from another whose ceiling permits more: the repository and its ceiling are part of what the
/// owner confirmed. Shown for the wider repository, it installs from that one.
#[tokio::test]
async fn kr_req_10_05_and_11_11_a_confirmation_for_a_narrow_repository_is_not_one_for_a_wider() {
    let host = host();
    let digest = synchronised(&host).await;
    let _: wire::CatalogueAddResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::CatalogueAdd,
                host.environment_id,
                &add_params_for(&host, "wide", vec!["terminal.transcript_tail".to_owned()]),
            ),
            Method::CatalogueAdd,
            Some(host.confirmations()),
        )
        .await);
    let _: wire::CatalogueSyncResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::CatalogueSync,
                host.environment_id,
                &wire::CatalogueSyncParams {
                    environment_id: host.environment_id,
                    catalogue_id: "wide".to_owned(),
                },
            ),
            Method::CatalogueSync,
            Some(host.confirmations()),
        )
        .await);
    let (narrow, wide) = (
        listed_ceiling(&host, "development").await,
        listed_ceiling(&host, "wide").await,
    );
    assert_ne!(narrow, wide);

    let shown = install_plan(&host, "development", &narrow, &digest, &[]);
    let refused = refusal(
        host.module
            .write_frame_admitted(
                &mutation(
                    Method::PluginInstall,
                    host.environment_id,
                    &confirmed_install(&host, "wide", &digest, &shown),
                ),
                Method::PluginInstall,
                Some(host.confirmations()),
            )
            .await,
    );
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(
        host.module
            .catalogue()
            .lock()
            .await
            .installation(host.environment_id, &plugin())
            .expect("readable")
            .is_none(),
        "nothing was installed"
    );

    let shown = install_plan(&host, "wide", &wide, &digest, &[]);
    let installed: wire::PluginInstallResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::PluginInstall,
                host.environment_id,
                &confirmed_install(&host, "wide", &digest, &shown),
            ),
            Method::PluginInstall,
            Some(host.confirmations()),
        )
        .await);
    assert_eq!(installed.plugin.catalogue_id, "wide");
}

/// A confirmation spent on an installation holds it to the ceiling the owner was shown. A ceiling
/// widened by another catalogue on the same directory after the confirmation was accepted, and
/// before the installation holds the repository, refuses the installation and installs nothing.
#[tokio::test]
async fn kr_req_10_05_and_11_11_a_ceiling_widened_after_the_confirmation_refuses_the_installation()
{
    let host = host();
    let digest = synchronised(&host).await;
    let ceiling = listed_ceiling(&host, "development").await;
    let root = host.module.catalogue().lock().await.root().to_path_buf();
    *host.ceremony.after_accept.lock().expect("the step") = Some(Box::new(move || {
        let mut other = kr_plugin_catalogue::Catalogue::open(&root).expect("a second catalogue");
        let id = RepositoryId::new("development").expect("a valid identifier");
        let mut enrolment = other.repository(&id).expect("readable").expect("enrolled");
        enrolment.ceiling =
            CapabilityCeiling::with([kr_plugin_sdk::capability::PluginCapability::TranscriptTail]);
        other
            .update_enrolment(enrolment, true)
            .expect("the owner widened it");
    }));

    let shown = install_plan(&host, "development", &ceiling, &digest, &[]);
    let refused = refusal(
        host.module
            .write_frame_admitted(
                &mutation(
                    Method::PluginInstall,
                    host.environment_id,
                    &confirmed_install(&host, "development", &digest, &shown),
                ),
                Method::PluginInstall,
                Some(host.confirmations()),
            )
            .await,
    );
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    assert!(refused.message.contains("ceiling"), "{refused:?}");
    assert!(
        host.module
            .catalogue()
            .lock()
            .await
            .installation(host.environment_id, &plugin())
            .expect("readable")
            .is_none(),
        "nothing was installed"
    );
}

/// Enrols and synchronises the development catalogue as the owner, and returns the example
/// package's hash.
async fn synchronised(host: &Host) -> String {
    let _: wire::CatalogueAddResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(Method::CatalogueAdd, host.environment_id, &add_params(host)),
            Method::CatalogueAdd,
            Some(host.confirmations()),
        )
        .await);
    let _: wire::CatalogueSyncResult = ok(host
        .module
        .write_frame_admitted(
            &mutation(
                Method::CatalogueSync,
                host.environment_id,
                &wire::CatalogueSyncParams {
                    environment_id: host.environment_id,
                    catalogue_id: "development".to_owned(),
                },
            ),
            Method::CatalogueSync,
            Some(host.confirmations()),
        )
        .await);
    let catalogue = host.module.catalogue().lock().await;
    let id = RepositoryId::new("development").expect("a valid identifier");
    catalogue
        .index(&id)
        .expect("an activated index")
        .find(
            &plugin(),
            &kr_plugin_sdk::version::PackageVersion::parse("0.1.0").expect("a version"),
        )
        .expect("the example package")
        .manifest_digest
        .to_string()
}

/// An answer that reads the catalogue's own records reports a record it cannot read as the
/// storage failure it is.
///
/// A capability answer and a plugin list read the repository's current index to say whether a
/// release is revoked, and a catalogue list reads the enrolments. An index document or a record
/// this host cannot read used to read as "no generation", which turned a disk fault into a
/// confident answer built from fallbacks. It is refused instead, under the code that sends
/// somebody to the disk.
#[tokio::test]
async fn a_record_this_host_cannot_read_is_a_storage_failure_in_every_answer() {
    let host = host();
    installed(&host).await;
    {
        let catalogue = host.module.catalogue().lock().await;
        let id = RepositoryId::new("development").expect("a valid identifier");
        let active = catalogue
            .active(&id)
            .expect("enrolled")
            .expect("a generation");
        let document = catalogue
            .store(&id)
            .expect("enrolled")
            .index_path(active.index_digest);
        std::fs::remove_file(document).expect("removable");
    }

    let capabilities = refusal(
        host.module
            .read_frame(
                ActorIngress::LocalIpc,
                &request(
                    Method::PluginCapabilities,
                    &wire::PluginCapabilitiesParams {
                        environment_id: host.environment_id,
                        plugin_id: plugin(),
                    },
                ),
            )
            .await,
    );
    assert_eq!(
        capabilities.code,
        ErrorCode::StorageUnavailable,
        "{capabilities:?}"
    );

    let plugins = refusal(
        host.module
            .read_frame(
                ActorIngress::LocalIpc,
                &request(
                    Method::PluginList,
                    &wire::PluginListParams {
                        environment_id: host.environment_id,
                    },
                ),
            )
            .await,
    );
    assert_eq!(plugins.code, ErrorCode::StorageUnavailable, "{plugins:?}");

    // An enrolment record this build cannot read is refused the same way.
    let database = host
        ._temp
        .environment()
        .state_dir()
        .join("catalogue")
        .join("catalogue.sqlite3");
    rusqlite::Connection::open(database)
        .expect("the catalogue's records")
        .execute(
            "UPDATE enrolments SET budgets = 'not the budgets this host wrote'",
            [],
        )
        .expect("written");
    let catalogues = refusal(
        host.module
            .read_frame(
                ActorIngress::LocalIpc,
                &request(
                    Method::CatalogueList,
                    &wire::CatalogueListParams {
                        environment_id: host.environment_id,
                    },
                ),
            )
            .await,
    );
    assert_eq!(
        catalogues.code,
        ErrorCode::StorageUnavailable,
        "{catalogues:?}"
    );
}

// ---------------------------------------------------------------------------------------------
// What an action that stops part way, or waits for the database, leaves in its receipt
// ---------------------------------------------------------------------------------------------

/// An admission that stands for every commit but the one that records the action's change, as
/// one withdrawn while an installation fetched its payloads and moved its package into place.
#[derive(Default)]
struct WithdrawnAtRecords {
    records: std::sync::atomic::AtomicUsize,
    others: std::sync::atomic::AtomicUsize,
}

impl Authority for WithdrawnAtRecords {
    fn check(&self) -> CatalogueResult<()> {
        Ok(())
    }

    fn commit(
        &self,
        effect: &Effect,
        commit: &mut dyn FnMut() -> CatalogueResult<()>,
    ) -> CatalogueResult<()> {
        if *effect == Effect::Records {
            self.records
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return Err(CatalogueError::Refused(
                kr_protocol::error::ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "withdrawn before the installation was recorded",
                ),
            ));
        }
        self.others
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        commit()
    }

    fn owner_confirmed(&self) -> bool {
        false
    }
}

impl Admission for WithdrawnAtRecords {
    fn accepted_deadline_ms(&self) -> Option<u64> {
        None
    }
}

/// An installation withdrawn after its package was in place is unknown, says what it left, and
/// is not performed again.
///
/// Its payloads were cached and its package moved into place under the admission, each in a
/// commit of its own, before the commit that records the installation was refused. Section 9
/// reserves refused for an action proved to have had no effect, so the receipt is unknown and the
/// answer names what the action left behind; a resubmission is told the same thing and performs
/// nothing.
#[tokio::test]
async fn an_installation_withdrawn_after_its_package_was_placed_is_unknown_and_not_repeated() {
    let host = host();
    let digest = synchronised(&host).await;
    let actor = ActorId::new("kr:actor:test").expect("a valid actor");
    let install = mutation(
        Method::PluginInstall,
        host.environment_id,
        &install_params(&host, &digest),
    );
    let admission = Arc::new(WithdrawnAtRecords::default());

    let answer = refusal(
        host.module
            .write_frame(
                &actor,
                &install,
                Method::PluginInstall,
                Some(host.confirmations()),
                admission.clone(),
            )
            .await,
    );
    assert_eq!(answer.code, ErrorCode::OutcomeUnknown, "{answer:?}");
    for said in [
        format!("the package {digest}"),
        "payloads written into the cache".to_owned(),
        "PERMISSION_DENIED: withdrawn before the installation was recorded".to_owned(),
    ] {
        assert!(answer.message.contains(&said), "{said} in {answer:?}");
    }
    let others = admission.others.load(std::sync::atomic::Ordering::SeqCst);
    assert!(others >= 2, "payloads and the package committed first");
    assert_eq!(
        admission.records.load(std::sync::atomic::Ordering::SeqCst),
        1
    );

    let read = host
        .module
        .action_read(&actor, install.action_id)
        .await
        .expect("readable")
        .expect("a receipt");
    assert_eq!(
        read.receipt.state,
        kr_protocol::receipt::ReceiptState::Unknown
    );
    assert_eq!(read.receipt.error.0.as_ref(), Some(&answer));

    let again = refusal(
        host.module
            .write_frame(
                &actor,
                &install,
                Method::PluginInstall,
                Some(host.confirmations()),
                admission.clone(),
            )
            .await,
    );
    assert_eq!(
        again, answer,
        "a resubmission is told what the first was told"
    );
    assert_eq!(
        admission.others.load(std::sync::atomic::Ordering::SeqCst),
        others,
        "and nothing is performed again"
    );
    assert_eq!(
        admission.records.load(std::sync::atomic::Ordering::SeqCst),
        1
    );
    let catalogue = host.module.catalogue().lock().await;
    assert!(
        catalogue
            .installation(host.environment_id, &plugin())
            .expect("readable")
            .is_none(),
        "the installation was never recorded"
    );
}

/// An admission whose second check, the catalogue's own after the claim, lets another writer take
/// the catalogue's database and hold it for a while.
///
/// The admission has a deadline, asked at every check and at the commit. Whatever `at_release`
/// does happens just before the other writer lets go.
struct WaitsForTheDatabase {
    database: std::path::PathBuf,
    deadline: std::time::Instant,
    hold: std::time::Duration,
    at_release: Arc<dyn Fn() + Send + Sync>,
    checks: std::sync::atomic::AtomicUsize,
    committed_at: std::sync::Mutex<Vec<std::time::Instant>>,
    holder: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl WaitsForTheDatabase {
    fn new(
        database: std::path::PathBuf,
        deadline: std::time::Duration,
        hold: std::time::Duration,
        at_release: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            database,
            deadline: std::time::Instant::now() + deadline,
            hold,
            at_release,
            checks: std::sync::atomic::AtomicUsize::new(0),
            committed_at: std::sync::Mutex::new(Vec::new()),
            holder: std::sync::Mutex::new(None),
        }
    }

    fn standing(&self) -> CatalogueResult<()> {
        if std::time::Instant::now() >= self.deadline {
            return Err(CatalogueError::Refused(
                kr_protocol::error::ProtocolError::new(
                    ErrorCode::PermissionDenied,
                    "the accepted deadline passed",
                ),
            ));
        }
        Ok(())
    }

    /// Waits for the other writer to finish, and returns when each commit was asked.
    fn finish(&self) -> Vec<std::time::Instant> {
        if let Some(holder) = self.holder.lock().expect("the holder").take() {
            holder.join().expect("the other writer let go");
        }
        self.committed_at.lock().expect("the commits").clone()
    }
}

impl Authority for WaitsForTheDatabase {
    fn check(&self) -> CatalogueResult<()> {
        self.standing()?;
        if self
            .checks
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            == 1
        {
            let (taken, held) = std::sync::mpsc::channel();
            let database = self.database.clone();
            let hold = self.hold;
            let at_release = Arc::clone(&self.at_release);
            let holder = std::thread::spawn(move || {
                let connection =
                    rusqlite::Connection::open(&database).expect("the catalogue's database");
                connection
                    .execute_batch("BEGIN IMMEDIATE")
                    .expect("the write lock");
                taken.send(()).expect("the admission is waiting");
                std::thread::sleep(hold);
                at_release();
                connection.execute_batch("ROLLBACK").expect("let go");
            });
            held.recv().expect("the other writer holds the lock");
            *self.holder.lock().expect("the holder") = Some(holder);
        }
        Ok(())
    }

    fn commit(
        &self,
        _effect: &Effect,
        commit: &mut dyn FnMut() -> CatalogueResult<()>,
    ) -> CatalogueResult<()> {
        self.committed_at
            .lock()
            .expect("the commits")
            .push(std::time::Instant::now());
        self.standing()?;
        commit()
    }

    fn owner_confirmed(&self) -> bool {
        false
    }
}

impl Admission for WaitsForTheDatabase {
    fn accepted_deadline_ms(&self) -> Option<u64> {
        None
    }
}

/// Where a host's catalogue keeps its records.
async fn database_of(host: &Host) -> std::path::PathBuf {
    host.module
        .catalogue()
        .lock()
        .await
        .root()
        .join(kr_plugin_catalogue::db::DATABASE_FILE)
}

/// A deadline that passes while a change waits for another writer's lock changes nothing.
///
/// The change takes the database's write lock before the admission is asked for the last time,
/// so the wait comes first and the deadline is asked after it, and a change that waited past its
/// deadline is refused rather than made late.
#[tokio::test]
async fn a_deadline_that_passes_while_the_change_waits_for_the_database_changes_nothing() {
    let host = host();
    synchronised(&host).await;
    let admission = Arc::new(WaitsForTheDatabase::new(
        database_of(&host).await,
        std::time::Duration::from_millis(800),
        std::time::Duration::from_millis(1_200),
        Arc::new(|| {}),
    ));
    let actor = ActorId::new("kr:actor:test").expect("a valid actor");
    let pin = mutation(
        Method::CataloguePin,
        host.environment_id,
        &wire::CataloguePinParams {
            environment_id: host.environment_id,
            catalogue_id: "development".to_owned(),
            generation: Nullable(Some(RepositoryGeneration::new(1))),
        },
    );

    let refused = refusal(
        host.module
            .write_frame(&actor, &pin, Method::CataloguePin, None, admission.clone())
            .await,
    );
    let committed_at = admission.finish();
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    assert!(refused.message.contains("deadline"), "{refused:?}");
    assert_eq!(committed_at.len(), 1, "the commit was asked once");
    assert!(
        committed_at[0] >= admission.deadline,
        "the commit was asked after the wait, when the deadline had passed"
    );

    let read = host
        .module
        .action_read(&actor, pin.action_id)
        .await
        .expect("readable")
        .expect("a receipt");
    assert_eq!(
        read.receipt.state,
        kr_protocol::receipt::ReceiptState::Refused
    );
    let catalogue = host.module.catalogue().lock().await;
    let id = RepositoryId::new("development").expect("a valid identifier");
    assert_eq!(
        catalogue
            .repository(&id)
            .expect("readable")
            .expect("enrolled")
            .pinned_generation,
        None,
        "nothing was pinned"
    );
}

/// An owner's confirmation that expires while its change waits for another writer's lock changes
/// nothing.
///
/// The confirmation is asked again inside the same commit, after the wait, so a root the owner
/// confirmed two minutes ago is not adopted now.
#[tokio::test]
async fn a_confirmation_that_expires_while_the_change_waits_for_the_database_changes_nothing() {
    let host = host();
    let ahead = Arc::clone(&host.ceremony.clock.ahead_ms);
    let admission = Arc::new(WaitsForTheDatabase::new(
        database_of(&host).await,
        std::time::Duration::from_secs(60),
        std::time::Duration::from_millis(300),
        Arc::new(move || {
            ahead.fetch_add(
                kr_pairing::confirm::CONFIRMATION_LIFETIME_MS + 1_000,
                std::sync::atomic::Ordering::SeqCst,
            );
        }),
    ));
    let actor = ActorId::new("kr:actor:test").expect("a valid actor");
    let add = mutation(
        Method::CatalogueAdd,
        host.environment_id,
        &add_params(&host),
    );

    let refused = refusal(
        host.module
            .write_frame(
                &actor,
                &add,
                Method::CatalogueAdd,
                Some(host.confirmations()),
                admission.clone(),
            )
            .await,
    );
    let committed_at = admission.finish();
    assert!(refused.message.contains("expired"), "{refused:?}");
    assert_eq!(
        committed_at.len(),
        1,
        "the commit was asked once, after the wait"
    );

    let read = host
        .module
        .action_read(&actor, add.action_id)
        .await
        .expect("readable")
        .expect("a receipt");
    assert_eq!(
        read.receipt.state,
        kr_protocol::receipt::ReceiptState::Refused
    );
    let catalogue = host.module.catalogue().lock().await;
    assert!(
        catalogue.repositories().expect("readable").is_empty(),
        "no root was adopted"
    );
}
