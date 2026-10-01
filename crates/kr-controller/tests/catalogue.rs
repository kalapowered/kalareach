//! The two plugin method groups, as the control daemon serves them.
//!
//! The catalogue's own rules are the runtime crate's and are tested there. What this covers is the
//! daemon's half: that both groups reach the module at all, that every method in them has one
//! exhaustive generated authority entry, that a request for another environment is refused before
//! anything is read, and that the answers carry the checks section 23 names for those two rows.

use std::path::Path;

use std::sync::Arc;

use kr_controller::catalogue::{Admission, CatalogueModule, TestingPoint};
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
    let module = CatalogueModule::open(
        &environment,
        None,
        Arc::new(kr_plugin_catalogue::UnboundBroker),
        kr_protocol::hostinfo::configuration::EnrolmentBudgets::default(),
        None,
        None,
    )
    .expect("an openable catalogue");
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
            None,
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
                None,
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
            None,
        )
        .await);
    assert_eq!(listed.plugins.len(), 1);
    assert_eq!(listed.plugins[0].catalogue_id, "development");
    assert_eq!(listed.plugins[0].live_bindings, Nullable::null());

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
            None,
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
    assert_eq!(removed.affected_bindings, Nullable::null());
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
            None,
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
    let reopened = CatalogueModule::open(
        &environment,
        None,
        Arc::new(kr_plugin_catalogue::UnboundBroker),
        kr_protocol::hostinfo::configuration::EnrolmentBudgets::default(),
        None,
        None,
    )
    .expect("the catalogue reopens");
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
                    None,
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
            None,
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
            None,
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
                None,
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
                None,
            )
            .await,
    );
    assert_eq!(expired.code, ErrorCode::PermissionDenied);
}

// ---------------------------------------------------------------------------------------------
// The disable policy a host starts with
// ---------------------------------------------------------------------------------------------

/// KR-REQ-25.22: the disable policy a host's configuration decides is recorded when the catalogue
/// opens, in the commit that raises the admission revision with it, so the first snapshot computed
/// carries it. Opening without one leaves the policy recorded, the same policy raises nothing,
/// another one raises the revision, and a record that cannot be read is replaced by the one the
/// configuration decides.
#[tokio::test(flavor = "multi_thread")]
async fn the_startup_policy_is_recorded_before_the_first_snapshot_is_computed() {
    use kr_protocol::admission::RevocationPolicy::{
        DisableAtNextAdmission, DisableAtOnce, WarnOnly,
    };
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let open = |policy| {
        CatalogueModule::open(
            &environment,
            None,
            Arc::new(kr_plugin_catalogue::UnboundBroker),
            kr_protocol::hostinfo::configuration::EnrolmentBudgets::default(),
            policy,
            None,
        )
        .expect("an openable catalogue")
    };
    let deadline = || tokio::time::Instant::now() + std::time::Duration::from_secs(30);

    let module = open(None);
    let before = module
        .admission_revision_within(deadline())
        .await
        .expect("a revision");
    module
        .snapshot_within(&[], deadline())
        .await
        .expect("computed");
    assert_eq!(module.policies_carried(), [WarnOnly]);
    drop(module);

    let module = open(Some(DisableAtOnce));
    let named = module
        .admission_revision_within(deadline())
        .await
        .expect("a revision");
    assert!(
        named > before,
        "the policy moved the revision: {named} {before}"
    );
    assert_eq!(module.disable_policy_in_force().await, Ok(DisableAtOnce));
    let first = module
        .snapshot_within(&[], deadline())
        .await
        .expect("computed");
    assert_eq!(first.policy, DisableAtOnce);
    assert_eq!(
        module.policies_carried(),
        [DisableAtOnce],
        "no snapshot was computed before the policy was in force"
    );
    drop(module);

    // The same policy, and no policy at all, leave what is recorded and the revision as they are.
    for policy in [Some(DisableAtOnce), None] {
        let module = open(policy);
        assert_eq!(module.disable_policy_in_force().await, Ok(DisableAtOnce));
        assert_eq!(
            module.admission_revision_within(deadline()).await,
            Ok(named),
            "{policy:?}"
        );
    }

    // Another policy replaces it and moves the revision.
    let module = open(Some(WarnOnly));
    assert_eq!(module.disable_policy_in_force().await, Ok(WarnOnly));
    assert!(
        module
            .admission_revision_within(deadline())
            .await
            .expect("a revision")
            > named
    );
    drop(module);

    // A record that cannot be read is what the configuration's policy replaces.
    let database = environment
        .state_dir()
        .join("catalogue")
        .join(kr_plugin_catalogue::db::DATABASE_FILE);
    rusqlite::Connection::open(database)
        .expect("the catalogue's records")
        .execute(
            "INSERT INTO settings (name, value) VALUES ('disable_policy', 'not a policy')
             ON CONFLICT (name) DO UPDATE SET value = excluded.value",
            [],
        )
        .expect("the damaged record");
    let module = open(None);
    assert!(module.disable_policy_in_force().await.is_err());
    drop(module);
    let module = open(Some(DisableAtNextAdmission));
    assert_eq!(
        module.disable_policy_in_force().await,
        Ok(DisableAtNextAdmission)
    );
}

/// KR-REQ-25.22: recording the policy when the catalogue opens forgets no release a worker that
/// outlived the last daemon may still hold. A commit forgets the releases an installation left
/// once no worker holds them, and a daemon that has not counted its workers yet cannot say that,
/// so its bridge says a worker is pending until it has. The control is the same commit once the
/// workers are counted, which forgets what none of them holds.
#[tokio::test(flavor = "multi_thread")]
async fn a_policy_recorded_at_open_forgets_no_release_a_surviving_worker_may_hold() {
    use kr_controller::catalogue::bridge::WorkerBridge;
    use kr_protocol::admission::RevocationPolicy::{DisableAtOnce, WarnOnly};
    let temp = kr_ipc::testing::TempHost::create();
    let environment = temp.environment();
    let open = |broker: Arc<dyn kr_plugin_catalogue::BrokerBridge>, policy| {
        CatalogueModule::open(
            &environment,
            None,
            broker,
            kr_protocol::hostinfo::configuration::EnrolmentBudgets::default(),
            policy,
            None,
        )
        .expect("an openable catalogue")
    };
    // The records exist, and hold a release an upgrade left while a worker may still bind it.
    drop(open(Arc::new(kr_plugin_catalogue::UnboundBroker), None));
    let database = environment
        .state_dir()
        .join("catalogue")
        .join(kr_plugin_catalogue::db::DATABASE_FILE);
    let retired = || -> i64 {
        rusqlite::Connection::open(&database)
            .expect("the catalogue's records")
            .query_row("SELECT COUNT(*) FROM retired_releases", [], |row| {
                row.get(0)
            })
            .expect("a count")
    };
    rusqlite::Connection::open(&database)
        .expect("the catalogue's records")
        .execute(
            "INSERT INTO retired_releases
                 (environment_id, plugin_id, package_digest, enrolment_key, repository_id, cap)
             VALUES (?1, 'kalareach/claude-code', ?2, ?3, 'development', '[]')",
            rusqlite::params![
                temp.environment_id().to_string(),
                kr_plugin_sdk::digest::PayloadDigest::of(b"a release").to_string(),
                kr_plugin_catalogue::EnrolmentKey::generate()
                    .expect("a key")
                    .as_str(),
            ],
        )
        .expect("a retired release");
    assert_eq!(retired(), 1);

    let bridge = Arc::new(WorkerBridge::new(
        kr_protocol::ids::ControllerGeneration::new(1),
    ));
    let module = open(bridge.clone(), Some(DisableAtOnce));
    assert_eq!(module.disable_policy_in_force().await, Ok(DisableAtOnce));
    assert_eq!(
        retired(),
        1,
        "a daemon that has not counted its workers forgets nothing"
    );

    bridge.members_known();
    assert_eq!(module.put_disable_policy_in_force(WarnOnly).await, Ok(true));
    assert_eq!(
        retired(),
        0,
        "with the workers counted, what none holds is forgotten"
    );
}

// ---------------------------------------------------------------------------------------------
// A disk error is a disk error in every answer
// ---------------------------------------------------------------------------------------------

/// A package check that stalls holds its snapshot to the bound and nothing else: the snapshot is
/// refused as busy by then, and the catalogue answers other work while the check is still held.
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_package_check_holds_its_snapshot_and_not_the_catalogue() {
    let host = host();
    let _ = installed(&host).await;
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = std::sync::Mutex::new(released);
    host.module.at_testing_point(move |point| {
        if point == TestingPoint::PackageChecks {
            let _ = released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .recv_timeout(std::time::Duration::from_secs(60));
        }
    });
    let bound = std::time::Duration::from_millis(300);
    let started = tokio::time::Instant::now();
    let stalled = host.module.snapshot_within(&[], started + bound).await;
    let waited = started.elapsed();
    assert_eq!(
        stalled.map(|_| ()).map_err(|error| error.code),
        Err(ErrorCode::ResourceUnavailable)
    );
    assert!(waited < bound * 4, "{waited:?}");
    let revision = host
        .module
        .admission_revision_within(tokio::time::Instant::now() + bound)
        .await;
    assert!(revision.is_ok(), "the catalogue answers: {revision:?}");
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
            None,
        )
        .await);
    assert_eq!(listed.plugins.len(), 1);
    drop(release);
}

/// A read of the records that stalls once the catalogue is held holds the cadence and a refresh
/// no longer than their bound: each is refused as busy by then, while the read is still held.
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_records_read_holds_the_cadence_no_longer_than_its_bound() {
    let host = host();
    let _ = installed(&host).await;
    let (release, released) = std::sync::mpsc::channel::<()>();
    let released = std::sync::Mutex::new(released);
    host.module.at_testing_point(move |point| {
        if point == TestingPoint::Records {
            let _ = released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .recv_timeout(std::time::Duration::from_secs(60));
        }
    });
    let bound = std::time::Duration::from_millis(300);
    let started = tokio::time::Instant::now();
    let installed = host.module.installed_within(started + bound).await;
    let waited = started.elapsed();
    assert_eq!(
        installed.map(|_| ()).map_err(|error| error.code),
        Err(ErrorCode::ResourceUnavailable)
    );
    assert!(waited < bound * 4, "{waited:?}");
    drop(release);
    let later = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    assert!(host.module.installed_within(later).await.is_ok());
    assert!(host.module.admission_revision_within(later).await.is_ok());
}

/// The doctor's evidence names each enrolled repository with the generation it activated, its
/// entries and what its metadata costs.
#[tokio::test]
async fn the_doctor_evidence_names_each_enrolled_repository() {
    let host = host();
    let before = host
        .module
        .evidence_within(tokio::time::Instant::now() + std::time::Duration::from_secs(30))
        .await
        .expect("readable");
    assert!(before.is_empty(), "nothing enrolled: {before:?}");
    let _ = synchronised(&host).await;
    let evidence = host
        .module
        .evidence_within(tokio::time::Instant::now() + std::time::Duration::from_secs(30))
        .await
        .expect("readable");
    assert_eq!(evidence.len(), 1, "{evidence:?}");
    let repository = &evidence[0];
    assert_eq!(repository.name, "development");
    assert!(repository.generation >= 1, "{repository:?}");
    assert!(repository.metadata_entries >= 1, "{repository:?}");
    assert!(repository.metadata_bytes > 0, "{repository:?}");
    assert!(!repository.degraded, "{repository:?}");
}

/// The configured enrolment budgets bound what `catalogue.add` may ask for: a request above one is
/// refused by name and enrols nothing, and an allowance configured above an SDK default (metadata
/// above 64 MiB, a full mirror) admits a request within it.
#[tokio::test]
async fn the_configured_budgets_bound_what_an_enrolment_may_ask_for() {
    use kr_protocol::hostinfo::configuration::EnrolmentBudgets;
    const MIB: u64 = 1024 * 1024;
    let host = host();
    let defaults = EnrolmentBudgets::default();
    let add = |params: wire::CatalogueAddParams| {
        let host = &host;
        async move {
            host.module
                .write_frame_admitted(
                    &mutation(Method::CatalogueAdd, host.environment_id, &params),
                    Method::CatalogueAdd,
                    Some(host.confirmations()),
                )
                .await
        }
    };
    let listed = || async {
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
                None,
            )
            .await);
        listed.catalogues.len()
    };

    host.module
        .put_budgets_in_force(EnrolmentBudgets {
            metadata_bytes: MIB,
            ..defaults
        })
        .await
        .expect("in force");
    let refused = refusal(add(add_params(&host)).await);
    assert_eq!(refused.code, ErrorCode::QuotaExceeded, "{refused:?}");
    assert!(refused.message.contains("metadata_bytes"), "{refused:?}");
    assert_eq!(listed().await, 0, "nothing enrolled");

    host.module
        .put_budgets_in_force(EnrolmentBudgets {
            full_offline_mirror: false,
            ..defaults
        })
        .await
        .expect("in force");
    let mut mirror = add_params(&host);
    mirror.budgets.full_offline_mirror = true;
    let refused = refusal(add(mirror).await);
    assert!(
        refused.message.contains("full_offline_mirror"),
        "{refused:?}"
    );
    assert_eq!(listed().await, 0, "nothing enrolled");

    host.module
        .put_budgets_in_force(EnrolmentBudgets {
            metadata_bytes: 128 * MIB,
            retained_metadata_bytes: 256 * MIB,
            full_offline_mirror: true,
            ..defaults
        })
        .await
        .expect("in force");
    let mut wide = add_params(&host);
    wide.budgets.metadata_bytes = U64::new(100 * MIB);
    wide.budgets.retained_metadata_bytes = U64::new(200 * MIB);
    wide.budgets.full_offline_mirror = true;
    let _: wire::CatalogueAddResult = ok(add(wide).await);
    assert_eq!(listed().await, 1);
}

/// The configured package limits hold each package, each no larger than the format's own: a
/// package past `package_bytes`, `object_count` or `expanded_pack_bytes` is refused by that name
/// and not installed, and within the limits it installs.
#[tokio::test]
async fn a_package_past_a_configured_package_limit_is_refused_by_name() {
    use kr_protocol::hostinfo::configuration::EnrolmentBudgets;
    let host = host();
    let digest = synchronised(&host).await;
    let install = || {
        let host = &host;
        let digest = digest.clone();
        async move {
            host.module
                .write_frame_admitted(
                    &mutation(
                        Method::PluginInstall,
                        host.environment_id,
                        &install_params(host, &digest),
                    ),
                    Method::PluginInstall,
                    Some(host.confirmations()),
                )
                .await
        }
    };
    let defaults = EnrolmentBudgets::default();
    for (name, budgets) in [
        (
            "package_bytes",
            EnrolmentBudgets {
                package_bytes: 1,
                ..defaults
            },
        ),
        (
            "object_count",
            EnrolmentBudgets {
                object_count: 1,
                ..defaults
            },
        ),
        (
            "expanded_pack_bytes",
            EnrolmentBudgets {
                expanded_pack_bytes: 1,
                ..defaults
            },
        ),
    ] {
        host.module
            .put_budgets_in_force(budgets)
            .await
            .expect("in force");
        let refused = refusal(install().await);
        assert!(
            matches!(
                refused.code,
                ErrorCode::QuotaExceeded | ErrorCode::OutcomeUnknown
            ),
            "{name}: {refused:?}"
        );
        assert!(refused.message.contains(name), "{name}: {refused:?}");
        let catalogue = host.module.catalogue().lock().await;
        assert!(
            catalogue
                .installation(host.environment_id, &plugin())
                .expect("readable")
                .is_none(),
            "{name}: nothing installed"
        );
    }
    host.module
        .put_budgets_in_force(defaults)
        .await
        .expect("in force");
    let _: wire::PluginInstallResult = ok(install().await);
}

/// A package already in the store is held to the limits in force as a fetched one is: installed,
/// removed, a limit lowered and installed again, it is refused by the limit's name.
#[tokio::test]
async fn a_package_kept_in_the_store_is_held_to_the_limits_in_force() {
    use kr_protocol::hostinfo::configuration::EnrolmentBudgets;
    let defaults = EnrolmentBudgets::default();
    for (name, budgets) in [
        (
            "package_bytes",
            EnrolmentBudgets {
                package_bytes: 1,
                ..defaults
            },
        ),
        (
            "object_count",
            EnrolmentBudgets {
                object_count: 1,
                ..defaults
            },
        ),
        (
            "expanded_pack_bytes",
            EnrolmentBudgets {
                expanded_pack_bytes: 1,
                ..defaults
            },
        ),
    ] {
        let host = host();
        let digest = installed(&host).await;
        let _: wire::PluginRemoveResult = ok(host
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
        host.module
            .put_budgets_in_force(budgets)
            .await
            .expect("in force");
        let refused = refusal(
            host.module
                .write_frame_admitted(
                    &mutation(
                        Method::PluginInstall,
                        host.environment_id,
                        &install_params(&host, &digest),
                    ),
                    Method::PluginInstall,
                    Some(host.confirmations()),
                )
                .await,
        );
        assert!(refused.message.contains(name), "{name}: {refused:?}");
        let catalogue = host.module.catalogue().lock().await;
        assert!(
            catalogue
                .installation(host.environment_id, &plugin())
                .expect("readable")
                .is_none(),
            "{name}: nothing installed"
        );
    }
}

/// A synchronisation holds each entry's declared size to `expanded_pack_bytes` as well as to
/// `package_bytes`, for an ordinary enrolment and for a full mirror: the generation is refused by
/// the limit's name and none is activated.
#[tokio::test]
async fn a_synchronisation_holds_each_entry_to_the_extracted_limit() {
    use kr_protocol::hostinfo::configuration::EnrolmentBudgets;
    for mirror in [false, true] {
        let host = host();
        host.module
            .put_budgets_in_force(EnrolmentBudgets {
                expanded_pack_bytes: 1,
                full_offline_mirror: mirror,
                ..EnrolmentBudgets::default()
            })
            .await
            .expect("in force");
        let mut params = add_params(&host);
        params.budgets.full_offline_mirror = mirror;
        let _: wire::CatalogueAddResult = ok(host
            .module
            .write_frame_admitted(
                &mutation(Method::CatalogueAdd, host.environment_id, &params),
                Method::CatalogueAdd,
                Some(host.confirmations()),
            )
            .await);
        let refused = refusal(
            host.module
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
                .await,
        );
        assert!(
            refused.message.contains("expanded_pack_bytes"),
            "mirror {mirror}: {refused:?}"
        );
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
                None,
            )
            .await);
        assert_eq!(
            listed.catalogues[0].generation,
            Nullable::null(),
            "mirror {mirror}: no generation activated"
        );
    }
}

/// The configured `transfer_bytes` holds every synchronisation: one that transfers more is refused
/// by that name and activates no generation, and within it the same synchronisation activates one.
#[tokio::test]
async fn a_synchronisation_is_held_to_the_configured_transfer_limit() {
    use kr_protocol::hostinfo::configuration::EnrolmentBudgets;
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
    let sync = || {
        let host = &host;
        async move {
            host.module
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
                .await
        }
    };
    let generation = || {
        let host = &host;
        async move {
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
                    None,
                )
                .await);
            listed.catalogues[0].generation
        }
    };

    host.module
        .put_budgets_in_force(EnrolmentBudgets {
            transfer_bytes: 1,
            ..EnrolmentBudgets::default()
        })
        .await
        .expect("in force");
    let refused = refusal(sync().await);
    assert_eq!(refused.code, ErrorCode::QuotaExceeded, "{refused:?}");
    assert!(refused.message.contains("transfer_bytes"), "{refused:?}");
    assert_eq!(
        generation().await,
        Nullable::null(),
        "no generation activated"
    );

    host.module
        .put_budgets_in_force(EnrolmentBudgets::default())
        .await
        .expect("in force");
    let _: wire::CatalogueSyncResult = ok(sync().await);
    assert_ne!(
        generation().await,
        Nullable::null(),
        "a generation activated"
    );
}

/// KR-REQ-23.29: a binding count is shown only at the admission revision it was read at.
///
/// Counts the workers gave at one admission revision are shown only while that is the revision
/// the answer renders: a change committed after the workers answered leaves them unknown.
#[tokio::test]
async fn counts_read_at_an_earlier_revision_are_not_shown() {
    let host = host();
    let _ = installed(&host).await;
    let current = host.module.admission_revision().await.expect("readable");
    let listed = |revision: u64| {
        let view = kr_controller::catalogue::bridge::LiveView {
            revision,
            live: std::collections::BTreeMap::new(),
            counts: Some(std::collections::BTreeMap::new()),
            admissions: None,
        };
        let host = &host;
        async move {
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
                    Some(&view),
                )
                .await);
            listed.plugins[0].live_bindings
        }
    };
    assert_eq!(listed(current).await, Nullable::some(U64::new(0)));
    assert_eq!(
        listed(current.saturating_sub(1)).await,
        Nullable::null(),
        "counts from before the last change are unknown"
    );
}

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
            None,
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
        let mut other = kr_plugin_catalogue::Catalogue::open(
            &root,
            std::sync::Arc::new(
                kr_plugin_catalogue::transport::RepositoryTransport::local_only(
                    "a test reads its repositories from disk",
                ),
            ),
        )
        .expect("a second catalogue");
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
                None,
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
                None,
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
                None,
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
                None,
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
    // The second is the bridge follow-up's rise of the admission revision, which the withdrawn
    // admission refuses too: nothing is written, and no bridge moves.
    assert_eq!(
        admission.records.load(std::sync::atomic::Ordering::SeqCst),
        2
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
                None,
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
        2
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
            .write_frame(
                &actor,
                &pin,
                Method::CataloguePin,
                None,
                admission.clone(),
                None,
            )
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
                None,
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

// ---------------------------------------------------------------------------------------------
// KR-REQ-11.42: a release's native bridge recipe, applied by the catalogue's own methods
// ---------------------------------------------------------------------------------------------

/// The catalogue's own builder of signed generations, for a release signed again with the build
/// records a test needs. This suite uses a few of its helpers.
#[allow(dead_code)]
#[path = "../../kr-plugin-catalogue/tests/support/mod.rs"]
mod generations;

/// The catalogue's plugin methods and a release that carries a native bridge recipe: the Claude
/// Code package 0.3.0 from the plugins repository's signed development generation, copied whole
/// into `tests/fixtures/bridge-generation/`, whose recipe installs three registration files and
/// one settings key in Claude Code's own directory.
mod native_bridges {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    #[cfg(unix)]
    use super::generations;

    use kr_controller::catalogue::native_bridge::{
        ApplicationDirectory, BridgeHost, BridgeSurface, QualifiedExecutable,
    };

    use super::*;

    /// Somebody's own settings, which the recipe adds one key to.
    const SETTINGS: &str = "{\n  \"model\": \"opus\"\n}\n";

    /// A stand-in for Claude Code's executable, hashed for its version and never run.
    const EXECUTABLE: &[u8] = b"\x7fELF a stand-in for Claude Code, hashed and never run";

    /// The capabilities release 0.3.0 asks for beyond a new enrolment's ceiling.
    const GRANT: [&str; 4] = [
        "approval.decode",
        "approval.respond",
        "native_bridge.install",
        "upstream.action",
    ];

    fn claude_code() -> PluginId {
        PluginId::new("kalareach/claude-code").expect("a plugin identifier")
    }

    fn generation() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bridge-generation")
    }

    /// Claude Code's directory, a search path with its executable, and the forwarder.
    struct Site {
        _temp: tempfile::TempDir,
        root: PathBuf,
        /// The signed qualification record the release would carry for the stand-in executable,
        /// at a version inside the recipe's range.
        signed_records: Vec<QualifiedExecutable>,
    }

    impl Site {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("a temporary directory");
            let root = temp.path().to_path_buf();
            let site = Self {
                _temp: temp,
                root,
                signed_records: vec![QualifiedExecutable {
                    digest: Digest256::from_bytes(kr_cbor::sha256(EXECUTABLE)),
                    version: "2.1.278".to_owned(),
                }],
            };
            std::fs::create_dir_all(site.application()).expect("Claude Code's directory");
            std::fs::write(site.application().join("settings.json"), SETTINGS).expect("settings");
            std::fs::create_dir_all(site.root.join("bin")).expect("a search path");
            std::fs::write(site.root.join("bin/claude"), EXECUTABLE).expect("an executable");
            std::fs::write(site.root.join("bin/kr-hook"), b"a stand-in forwarder")
                .expect("a forwarder");
            site
        }

        fn application(&self) -> PathBuf {
            self.root.join("home/.claude")
        }

        fn bridges(&self, environment: &kr_ipc::paths::EnvironmentPaths) -> BridgeHost {
            BridgeHost {
                journals: environment.state_dir().join("native-bridges"),
                applications: vec![ApplicationDirectory {
                    application: "Claude Code".to_owned(),
                    directory: self.application(),
                }],
                search_path: vec![self.root.join("bin")],
                forwarder: Some(self.root.join("bin/kr-hook")),
                signed_records: self.signed_records.clone(),
            }
        }

        /// Every file under Claude Code's directory, with its bytes, and every directory.
        fn tree(&self) -> BTreeMap<String, Option<Vec<u8>>> {
            let mut found = BTreeMap::new();
            let mut pending = vec![self.application()];
            while let Some(directory) = pending.pop() {
                for entry in std::fs::read_dir(&directory).expect("readable") {
                    let path = entry.expect("an entry").path();
                    let name = path
                        .strip_prefix(self.application())
                        .expect("inside")
                        .to_string_lossy()
                        .into_owned();
                    if path.is_dir() {
                        found.insert(name, None);
                        pending.push(path);
                    } else {
                        found.insert(name, Some(std::fs::read(&path).expect("a file")));
                    }
                }
            }
            found
        }
    }

    /// A daemon-hosted catalogue over a copy of the bridge generation, applying bridges in the
    /// site.
    fn host(site: &Site) -> Host {
        let temp = kr_ipc::testing::TempHost::create();
        let environment = temp.environment();
        let environment_id = temp.environment_id();
        let module = CatalogueModule::open_with(
            &environment,
            None,
            site.bridges(&environment),
            Arc::new(kr_plugin_catalogue::UnboundBroker),
            kr_protocol::hostinfo::configuration::EnrolmentBudgets::default(),
            None,
            None,
        )
        .expect("an openable catalogue");
        let working_temp = tempfile::tempdir().expect("a temporary directory");
        let working = working_temp.path().join("development");
        copy_tree(&generation(), &working);
        Host {
            _temp: temp,
            module,
            environment_id,
            working,
            _working_temp: working_temp,
            ceremony: Ceremony::new(),
        }
    }

    /// The daemon started again over the same environment and site.
    fn restarted(host: &mut Host, site: &Site) {
        let environment = host._temp.environment();
        host.module = CatalogueModule::open_with(
            &environment,
            None,
            site.bridges(&environment),
            Arc::new(kr_plugin_catalogue::UnboundBroker),
            kr_protocol::hostinfo::configuration::EnrolmentBudgets::default(),
            None,
            None,
        )
        .expect("an openable catalogue");
    }

    /// Enrols and synchronises the bridge generation, and returns release 0.3.0's hash.
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
        catalogue
            .index(&RepositoryId::new("development").expect("a valid identifier"))
            .expect("an activated index")
            .find(
                &claude_code(),
                &kr_plugin_sdk::version::PackageVersion::parse("0.3.0").expect("a version"),
            )
            .expect("release 0.3.0")
            .manifest_digest
            .to_string()
    }

    /// The installation of release 0.3.0 with the grant it needs, carrying the owner's
    /// confirmation of exactly that installation when `confirmed`.
    async fn install(host: &Host, digest: &str, confirmed: bool) -> ControlFrame {
        let grant: Vec<String> = GRANT.iter().map(|name| (*name).to_owned()).collect();
        let owner_confirmation = if confirmed {
            let ceiling = listed_ceiling(host, "development").await;
            let plan = PluginInstallPlan {
                environment_id: host.environment_id,
                catalogue_id: "development".to_owned(),
                ceiling: ceiling.into_iter().collect(),
                plugin_id: claude_code(),
                version: "0.3.0".to_owned(),
                package_digest: digest.to_owned(),
                grant: grant.iter().cloned().collect(),
            };
            Nullable::some(host.ceremony.approve(
                SensitiveAction::GrantExecutableCapability,
                plan.action_digest().expect("a digest"),
            ))
        } else {
            Nullable::null()
        };
        let params = wire::PluginInstallParams {
            environment_id: host.environment_id,
            catalogue_id: "development".to_owned(),
            plugin_id: claude_code(),
            version: "0.3.0".to_owned(),
            package_digest: digest.to_owned(),
            grant,
            owner_confirmation,
        };
        host.module
            .write_frame_admitted(
                &mutation(Method::PluginInstall, host.environment_id, &params),
                Method::PluginInstall,
                Some(host.confirmations()),
            )
            .await
    }

    /// Installs release 0.3.0 with the owner's confirmation and enables it, which is when its
    /// recipe is wanted.
    async fn installed_and_enabled(host: &Host, digest: &str) -> wire::PluginInstallResult {
        let installed = ok(install(host, digest, true).await);
        let _: wire::PluginEnableResult = ok(plugin_change(host, Method::PluginEnable).await);
        installed
    }

    /// Serves one plugin mutation that needs no confirmation.
    async fn plugin_change(host: &Host, method: Method) -> ControlFrame {
        let params = match method {
            Method::PluginRemove => ParamsValue::from_typed(&wire::PluginRemoveParams {
                environment_id: host.environment_id,
                plugin_id: claude_code(),
            }),
            _ => ParamsValue::from_typed(&wire::PluginEnableParams {
                environment_id: host.environment_id,
                plugin_id: claude_code(),
            }),
        }
        .expect("serialisable");
        let mut change = mutation(method, host.environment_id, &serde_json::json!({}));
        change.params = params;
        host.module
            .write_frame_admitted(&change, method, Some(host.confirmations()))
            .await
    }

    fn bridge_facts(
        host: &Host,
        digest: &str,
    ) -> Option<kr_controller::catalogue::native_bridge::BridgeFacts> {
        host.module
            .native_bridges()
            .facts(
                &claude_code(),
                kr_plugin_sdk::digest::PayloadDigest::parse(digest).expect("a package hash"),
            )
            .expect("readable")
    }

    /// What the daemon records for release 0.3.0 on Windows, where this host applies no native
    /// bridge: the recipe is refused before anything is written, nothing is applied, and the
    /// refusal is on record with its reason.
    fn refused_on_windows(host: &Host, digest: &str) {
        assert!(bridge_facts(host, digest).is_none(), "nothing is applied");
        let reports = host.module.native_bridges().reports().expect("reads");
        assert_eq!(reports.len(), 1, "{reports:?}");
        assert_eq!(reports[0].state, "refused", "{reports:?}");
        assert!(
            reports[0]
                .notes
                .iter()
                .any(|note| note.contains("does not apply or remove a native bridge on Windows")),
            "{reports:?}"
        );
    }

    /// The directory as the recipe leaves it, from what it held before.
    fn applied(
        before: &BTreeMap<String, Option<Vec<u8>>>,
        generation: &Path,
    ) -> BTreeMap<String, Option<Vec<u8>>> {
        let bridge = generation.join("targets/packages/kalareach/claude-code/0.3.0/bridge");
        let mut expected = before.clone();
        for directory in [
            "skills",
            "skills/kalareach-channels",
            "skills/kalareach-channels/.claude-plugin",
            "skills/kalareach-channels/hooks",
        ] {
            expected.insert(directory.to_owned(), None);
        }
        for (path, source) in [
            (
                "skills/kalareach-channels/.claude-plugin/plugin.json",
                "plugin-manifest.json",
            ),
            ("skills/kalareach-channels/.mcp.json", "mcp-servers.json"),
            ("skills/kalareach-channels/hooks/hooks.json", "hooks.json"),
        ] {
            expected.insert(
                path.to_owned(),
                Some(std::fs::read(bridge.join(source)).expect("a release file")),
            );
        }
        expected.insert(
            "settings.json".to_owned(),
            Some(
                "{\n  \"model\": \"opus\",\n  \"enabledPlugins\": {\"kalareach-channels@skills-dir\": true}\n}\n"
                    .as_bytes()
                    .to_vec(),
            ),
        );
        expected
    }

    /// KR-REQ-11.42: an installation the owner confirmed applies its release's recipe once it is
    /// enabled and committed, and not while it is only installed; a refused confirmation installs
    /// nothing and writes nothing; a disable takes the registration out and an enable puts it back;
    /// a removal restores Claude Code's directory. On Windows the recipe is refused and recorded
    /// when it is wanted, and nothing is written in Claude Code's directory at any step.
    #[tokio::test]
    async fn kr_req_11_42_a_confirmed_installation_applies_the_recipe_once_enabled_and_its_removal_undoes_it()
     {
        let site = Site::new();
        let host = host(&site);
        let digest = synchronised(&host).await;
        let before = site.tree();

        let refused = refusal(install(&host, &digest, false).await);
        assert_eq!(
            refused.code,
            ErrorCode::OwnerConfirmationRequired,
            "{refused:?}"
        );
        assert_eq!(site.tree(), before, "a refused confirmation writes nothing");
        assert!(
            host.module
                .native_bridges()
                .reports()
                .expect("reads")
                .is_empty()
        );

        // Installed and not enabled: the owner has confirmed the grant and has not turned the
        // package on, so nothing runs in the application's name.
        let installed: wire::PluginInstallResult = ok(install(&host, &digest, true).await);
        assert_eq!(installed.plugin.package_digest, digest);
        assert_eq!(
            site.tree(),
            before,
            "an installation that is not enabled places nothing"
        );
        assert!(bridge_facts(&host, &digest).is_none());
        assert!(
            host.module
                .native_bridges()
                .reports()
                .expect("reads")
                .is_empty()
        );

        // Control: enabling it applies the recipe.
        let _: wire::PluginEnableResult = ok(plugin_change(&host, Method::PluginEnable).await);
        let placed = if cfg!(windows) {
            before.clone()
        } else {
            applied(&before, &host.working)
        };
        assert_eq!(
            site.tree(),
            placed,
            "the recipe's files and key, and nothing else"
        );
        if cfg!(windows) {
            refused_on_windows(&host, &digest);
        } else {
            let facts = bridge_facts(&host, &digest).expect("applied");
            assert_eq!(facts.application, "claude-code");
            assert_eq!(
                facts.surfaces,
                [BridgeSurface::Hook, BridgeSurface::Channel]
                    .into_iter()
                    .collect()
            );
            assert_eq!(facts.forwarder, site.root.join("bin/kr-hook"));
        }

        let _: wire::PluginEnableResult = ok(plugin_change(&host, Method::PluginDisable).await);
        assert_eq!(
            site.tree(),
            before,
            "a disabled package's registration is taken out"
        );
        assert!(bridge_facts(&host, &digest).is_none());
        let _: wire::PluginEnableResult = ok(plugin_change(&host, Method::PluginEnable).await);
        assert_eq!(site.tree(), placed, "enabling it again puts it back");

        let _: wire::PluginRemoveResult = ok(plugin_change(&host, Method::PluginRemove).await);
        assert_eq!(
            site.tree(),
            before,
            "Claude Code's directory is what it was"
        );
        assert!(bridge_facts(&host, &digest).is_none());
        assert!(
            host.module
                .native_bridges()
                .reports()
                .expect("reads")
                .is_empty()
        );
    }

    /// KR-REQ-11.42: a grant that withdraws the bridge's capability takes the registration out,
    /// and the installation stays. On Windows there is no registration to take out: the recipe
    /// was refused and recorded when the installation committed.
    #[tokio::test]
    async fn kr_req_11_42_withdrawing_the_bridge_grant_takes_the_registration_out() {
        let site = Site::new();
        let host = host(&site);
        let digest = synchronised(&host).await;
        let before = site.tree();
        let _: wire::PluginInstallResult = installed_and_enabled(&host, &digest).await;
        if cfg!(windows) {
            assert_eq!(site.tree(), before);
            refused_on_windows(&host, &digest);
        } else {
            assert_ne!(site.tree(), before);
        }

        let narrower: Vec<String> = GRANT
            .iter()
            .filter(|name| **name != "native_bridge.install")
            .map(|name| (*name).to_owned())
            .collect();
        let plan = PluginGrantPlan {
            environment_id: host.environment_id,
            plugin_id: claude_code(),
            version: "0.3.0".to_owned(),
            package_digest: digest.clone(),
            grant: narrower.iter().cloned().collect(),
        };
        let params = wire::PluginGrantParams {
            environment_id: host.environment_id,
            plugin_id: claude_code(),
            package_digest: digest.clone(),
            grant: narrower,
            owner_confirmation: host.ceremony.approve(
                SensitiveAction::GrantExecutableCapability,
                plan.action_digest().expect("a digest"),
            ),
        };
        let _: wire::PluginGrantResult = ok(host
            .module
            .write_frame_admitted(
                &mutation(Method::PluginGrant, host.environment_id, &params),
                Method::PluginGrant,
                Some(host.confirmations()),
            )
            .await);

        assert_eq!(site.tree(), before, "the registration is taken out");
        assert!(bridge_facts(&host, &digest).is_none());
        let catalogue = host.module.catalogue().lock().await;
        assert!(
            catalogue
                .installation(host.environment_id, &claude_code())
                .expect("readable")
                .is_some(),
            "the installation stays"
        );
    }

    /// KR-REQ-11.42: a restarted daemon reads the record back, and changes nothing that is already
    /// in place. On Windows the record it reads back is the refusal.
    #[tokio::test]
    async fn kr_req_11_42_a_restart_reads_the_record_back() {
        let site = Site::new();
        let mut host = host(&site);
        let digest = synchronised(&host).await;
        let _: wire::PluginInstallResult = installed_and_enabled(&host, &digest).await;
        let after = site.tree();
        let before_restart = bridge_facts(&host, &digest);
        if cfg!(windows) {
            refused_on_windows(&host, &digest);
        } else {
            assert!(before_restart.is_some(), "applied");
        }

        restarted(&mut host, &site);

        assert_eq!(bridge_facts(&host, &digest), before_restart);
        if cfg!(windows) {
            refused_on_windows(&host, &digest);
        }
        assert_eq!(site.tree(), after, "nothing was written again");
    }

    /// Installs Claude Code's package and enables it with its bridge stopped part way, and returns
    /// the package hash: the bridge is not applied.
    #[cfg(unix)]
    async fn stopped_part_way(host: &Host) -> String {
        let digest = synchronised(host).await;
        let _: wire::PluginInstallResult = ok(install(host, &digest, true).await);
        host.module.native_bridges().stop_before(20);
        let _: wire::PluginEnableResult = ok(plugin_change(host, Method::PluginEnable).await);
        assert!(bridge_facts(host, &digest).is_none(), "stopped part way");
        host.module.native_bridges().stop_before(0);
        digest
    }

    /// A pin the catalogue refuses, whose bridge follow-up finishes what was stopped.
    #[cfg(unix)]
    async fn refused_pin(host: &Host, digest: &str) {
        let mut wrong = digest.to_owned();
        let last = wrong.pop().expect("a hash");
        wrong.push(if last == '0' { '1' } else { '0' });
        let _ = refusal(
            host.module
                .write_frame_admitted(
                    &mutation(
                        Method::PluginPin,
                        host.environment_id,
                        &wire::PluginPinParams {
                            environment_id: host.environment_id,
                            plugin_id: claude_code(),
                            package_digest: Nullable(Some(wrong)),
                        },
                    ),
                    Method::PluginPin,
                    Some(host.confirmations()),
                )
                .await,
        );
        assert!(
            bridge_facts(host, digest).is_some(),
            "the follow-up finished it"
        );
    }

    #[cfg(unix)]
    fn bridged(snapshot: &kr_controller::catalogue::admissions::Snapshot) -> bool {
        snapshot
            .packages
            .iter()
            .any(|package| package.bridge.is_present())
    }

    /// A change that follows a bridge raises the admission revision even when the change itself
    /// is refused: the bridge it moved is handed over at a revision above every snapshot computed
    /// before it, and every worker is sent a round for it.
    ///
    /// Windows applies no native bridge (`refused_on_windows`), so this runs on the other
    /// platforms.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_bridge_followed_by_a_refused_change_raises_the_admission_revision() {
        let site = Site::new();
        let host = host(&site);
        let digest = stopped_part_way(&host).await;
        let later = || tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        let before = host
            .module
            .snapshot_within(&[], later())
            .await
            .expect("computed");
        assert!(!before.packages.is_empty() && !bridged(&before));

        refused_pin(&host, &digest).await;

        let after = host
            .module
            .snapshot_within(&[], later())
            .await
            .expect("computed");
        assert!(
            after.revision > before.revision,
            "{} {}",
            after.revision,
            before.revision
        );
        assert!(bridged(&after));
    }

    /// A snapshot whose package checks were still running when a change moved a bridge carries a
    /// lower revision than the snapshot computed after the change, so a round that hands it over
    /// later is still below the one that handed over the newer one.
    ///
    /// Windows applies no native bridge (`refused_on_windows`), so this runs on the other
    /// platforms.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_snapshot_computed_across_a_bridge_move_is_below_the_one_after_it() {
        let site = Site::new();
        let host = host(&site);
        let digest = stopped_part_way(&host).await;
        let (entered, entering) = std::sync::mpsc::channel::<()>();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let entered = std::sync::Mutex::new(entered);
        let released = std::sync::Mutex::new(released);
        let first = std::sync::atomic::AtomicBool::new(true);
        host.module.at_testing_point(move |point| {
            if point == TestingPoint::PackageChecks
                && first.swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                let _ = entered
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .send(());
                let _ = released
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .recv_timeout(std::time::Duration::from_secs(60));
            }
        });
        let later = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        let moving = async {
            tokio::task::spawn_blocking(move || {
                entering.recv_timeout(std::time::Duration::from_secs(60))
            })
            .await
            .expect("the wait ended")
            .expect("the first snapshot is checking its packages");
            refused_pin(&host, &digest).await;
            let newer = host
                .module
                .snapshot_within(&[], later)
                .await
                .expect("computed");
            drop(release);
            newer
        };
        let (older, newer) = tokio::join!(host.module.snapshot_within(&[], later), moving);
        let older = older.expect("computed");
        assert!(!bridged(&older) && bridged(&newer));
        assert!(
            older.revision < newer.revision,
            "{} {}",
            older.revision,
            newer.revision
        );
    }

    /// A change that holds the catalogue (here, one whose bridge is being placed) holds a round's
    /// snapshot and revision no longer than the bound the round gives them: both are refused as
    /// busy while the change still holds it, and both are answered once the change is done.
    ///
    /// Windows applies no native bridge (`refused_on_windows`), so this runs on the other
    /// platforms.
    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_busy_catalogue_holds_a_round_no_longer_than_its_bound() {
        let site = Site::new();
        let host = host(&site);
        let digest = synchronised(&host).await;
        let _: wire::PluginInstallResult = ok(install(&host, &digest, true).await);
        let (entered, entering) = std::sync::mpsc::channel::<()>();
        let (release, released) = std::sync::mpsc::channel::<()>();
        let entered = std::sync::Mutex::new(entered);
        let released = std::sync::Mutex::new(released);
        host.module.native_bridges().before_publishing(move |_| {
            let _ = entered
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .send(());
            let _ = released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .recv_timeout(std::time::Duration::from_secs(60));
        });
        let bound = std::time::Duration::from_millis(300);
        let asking = async {
            let entering = tokio::task::spawn_blocking(move || {
                entering.recv_timeout(std::time::Duration::from_secs(60))
            });
            entering
                .await
                .expect("the wait ended")
                .expect("the change is placing its bridge");
            let snapshot = host
                .module
                .snapshot_within(&[], tokio::time::Instant::now() + bound)
                .await;
            let revision = host
                .module
                .admission_revision_within(tokio::time::Instant::now() + bound)
                .await;
            drop(release);
            (snapshot.map(|_| ()), revision)
        };
        let (enabled, (snapshot, revision)) =
            tokio::join!(plugin_change(&host, Method::PluginEnable), asking);
        let _: wire::PluginEnableResult = ok(enabled);
        assert_eq!(
            snapshot.map_err(|error| error.code),
            Err(ErrorCode::ResourceUnavailable)
        );
        assert_eq!(
            revision.map_err(|error| error.code),
            Err(ErrorCode::ResourceUnavailable)
        );
        let later = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        assert!(host.module.snapshot_within(&[], later).await.is_ok());
        assert!(host.module.admission_revision_within(later).await.is_ok());
    }

    /// An application that stops part way is not reported as applied, and the daemon's next start
    /// finishes it. On Windows the next start refuses the recipe again and writes nothing.
    #[tokio::test]
    async fn an_application_stopped_part_way_is_finished_when_the_daemon_starts_again() {
        let site = Site::new();
        let mut host = host(&site);
        let digest = synchronised(&host).await;
        let before = site.tree();
        let installed: wire::PluginInstallResult = ok(install(&host, &digest, true).await);
        host.module.native_bridges().stop_before(20);
        let _: wire::PluginEnableResult = ok(plugin_change(&host, Method::PluginEnable).await);

        assert_eq!(
            installed.plugin.package_digest, digest,
            "the installation's answer stands"
        );
        assert!(
            bridge_facts(&host, &digest).is_none(),
            "not reported as applied"
        );
        restarted(&mut host, &site);
        if cfg!(windows) {
            assert_eq!(
                site.tree(),
                before,
                "nothing is written at the start either"
            );
            refused_on_windows(&host, &digest);
        } else {
            assert_eq!(
                site.tree(),
                applied(&before, &host.working),
                "finished at the start"
            );
            assert!(bridge_facts(&host, &digest).is_some());
        }
    }

    /// With no signed record establishing the executable's version, as in the committed
    /// generation, which names no builds, a confirmed installation commits and its recipe places
    /// nothing, and says why. On Windows the reason is the platform's, which is checked first.
    #[tokio::test]
    async fn a_release_without_signed_version_evidence_places_nothing() {
        let site = Site {
            signed_records: Vec::new(),
            ..Site::new()
        };
        let host = host(&site);
        let digest = synchronised(&host).await;
        let before = site.tree();

        let installed: wire::PluginInstallResult = installed_and_enabled(&host, &digest).await;

        assert_eq!(installed.plugin.package_digest, digest);
        assert_eq!(site.tree(), before, "nothing was placed");
        if cfg!(windows) {
            refused_on_windows(&host, &digest);
            return;
        }
        let reports = host.module.native_bridges().reports().expect("reads");
        assert_eq!(reports.len(), 1, "{reports:?}");
        assert_eq!(reports[0].state, "refused");
        assert!(
            reports[0]
                .notes
                .iter()
                .any(|note| note.contains("no signed qualification record")),
            "{reports:?}"
        );
    }

    /// The platform a build of the stand-in executable runs on: this host's, or one release
    /// 0.3.0 also lists.
    #[cfg(unix)]
    fn stand_in_on(
        os: kr_plugin_sdk::matching::OperatingSystem,
        architecture: kr_plugin_sdk::matching::Architecture,
    ) -> kr_plugin_sdk::catalogue::QualifiedBuild {
        kr_plugin_sdk::catalogue::QualifiedBuild {
            application: kr_plugin_sdk::text::Label::new("claude-code").expect("a label"),
            distribution: kr_plugin_sdk::text::Label::new("npm @anthropic-ai/claude-code")
                .expect("a label"),
            version: kr_plugin_sdk::version::PackageVersion::parse("2.1.278").expect("a version"),
            os,
            architecture,
            executable_digest: kr_plugin_sdk::digest::PayloadDigest::of(EXECUTABLE),
        }
    }

    /// Names the stand-in executable at 2.1.278, built for this host.
    #[cfg(unix)]
    fn built_here(entry: &mut kr_plugin_sdk::catalogue::IndexEntry) {
        let here = kr_plugin_catalogue::this_host();
        entry.builds = vec![stand_in_on(
            here.os.expect("a named platform"),
            here.architecture.expect("a named platform"),
        )];
    }

    /// Names the stand-in executable at 2.1.278, built only for a platform other than this host's.
    #[cfg(unix)]
    fn built_elsewhere(entry: &mut kr_plugin_sdk::catalogue::IndexEntry) {
        use kr_plugin_sdk::matching::{Architecture, OperatingSystem};
        let here = kr_plugin_catalogue::this_host();
        entry.builds = vec![if here.os == Some(OperatingSystem::MacOs) {
            stand_in_on(OperatingSystem::Linux, Architecture::X86_64)
        } else {
            stand_in_on(OperatingSystem::MacOs, Architecture::Aarch64)
        }];
    }

    /// The bridge generation's release 0.3.0 signed again as generation `number` of a repository
    /// of this test's own, its entry edited by `edit`, and put where the host reads its
    /// repository from.
    #[cfg(unix)]
    async fn signed_again(
        host: &Host,
        home: &Path,
        keys: Option<generations::KeySet>,
        number: u64,
        edit: Option<fn(&mut kr_plugin_sdk::catalogue::IndexEntry)>,
    ) -> generations::KeySet {
        let package = home.join("claude-code-0.3.0");
        if !package.exists() {
            copy_tree(
                &generation().join("targets/packages/kalareach/claude-code/0.3.0"),
                &package,
            );
        }
        let built = generations::Generation::build(
            &home.join(format!("generation-{number}")),
            generations::GenerationSpec {
                generation: number,
                package: Some(package),
                keys,
                edit_entry: edit,
                ..generations::GenerationSpec::default()
            },
        )
        .await;
        let _ = std::fs::remove_dir_all(&host.working);
        copy_tree(&built.directory(), &host.working);
        built.keys()
    }

    /// Synchronises the repository this test enrolled.
    #[cfg(unix)]
    async fn sync(host: &Host) {
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
    }

    /// The recipe's version is read from the signed builds the installed release's current entry
    /// names: with none for this host, and with one only for another platform, the recipe places
    /// nothing; a synchronisation that adds the build for this host applies it, with no change to
    /// the plugin, and the facts then name the release.
    ///
    /// Windows applies no native bridge (`refused_on_windows`), so this runs on the other
    /// platforms.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_recipe_applies_once_a_synchronised_record_names_this_hosts_build() {
        let site = Site {
            signed_records: Vec::new(),
            ..Site::new()
        };
        let host = host(&site);
        let home = tempfile::tempdir().expect("a temporary directory");
        let keys = signed_again(&host, home.path(), None, 1, None).await;
        let digest = synchronised(&host).await;
        let before = site.tree();

        let _: wire::PluginInstallResult = installed_and_enabled(&host, &digest).await;
        assert_eq!(site.tree(), before, "no record: nothing was placed");

        signed_again(
            &host,
            home.path(),
            Some(keys.clone()),
            2,
            Some(built_elsewhere),
        )
        .await;
        sync(&host).await;
        assert_eq!(
            site.tree(),
            before,
            "a record for another platform places nothing"
        );
        assert!(bridge_facts(&host, &digest).is_none());

        signed_again(&host, home.path(), Some(keys), 3, Some(built_here)).await;
        sync(&host).await;
        assert_eq!(
            site.tree(),
            applied(&before, &generation()),
            "the synchronised record applies the recipe"
        );
        assert!(bridge_facts(&host, &digest).is_some());
    }

    /// Marks release 0.3.0's entry revoked, as a later generation publishes it.
    #[cfg(unix)]
    fn revoked(entry: &mut kr_plugin_sdk::catalogue::IndexEntry) {
        entry.revocation = Nullable(Some(kr_plugin_sdk::catalogue::RevocationRecord {
            reason: kr_plugin_sdk::catalogue::RevocationReason::Vulnerable,
            revoked_at: kr_plugin_sdk::scalars::TimestampMs::new(1_760_000_100_000),
            statement: kr_plugin_sdk::text::Summary::new("Replaced by 0.3.1")
                .expect("a valid statement"),
        }));
    }

    /// KR-REQ-11.42, KR-REQ-25.22: a release its repository revokes keeps no registration in the
    /// application's directory. A synchronisation that publishes the revocation takes the recipe
    /// out and the installation stays; the control is a generation that revokes nothing, which
    /// leaves the registration where it is.
    ///
    /// Windows applies no native bridge (`refused_on_windows`), so this runs on the other
    /// platforms.
    #[cfg(unix)]
    #[tokio::test]
    async fn kr_req_11_42_a_revoked_release_keeps_no_registration() {
        let site = Site::new();
        let host = host(&site);
        let home = tempfile::tempdir().expect("a temporary directory");
        let keys = signed_again(&host, home.path(), None, 1, None).await;
        let digest = synchronised(&host).await;
        let before = site.tree();
        let _: wire::PluginInstallResult = installed_and_enabled(&host, &digest).await;
        let placed = applied(&before, &generation());
        assert_eq!(site.tree(), placed, "applied");

        signed_again(&host, home.path(), Some(keys.clone()), 2, None).await;
        sync(&host).await;
        assert_eq!(
            site.tree(),
            placed,
            "a generation that revokes nothing leaves the registration"
        );
        assert!(bridge_facts(&host, &digest).is_some());

        signed_again(&host, home.path(), Some(keys), 3, Some(revoked)).await;
        sync(&host).await;
        assert_eq!(
            site.tree(),
            before,
            "the revoked release's registration is out"
        );
        assert!(bridge_facts(&host, &digest).is_none());
        let catalogue = host.module.catalogue().lock().await;
        assert!(
            catalogue
                .installation(host.environment_id, &claude_code())
                .expect("readable")
                .is_some(),
            "the installation stays"
        );
    }

    /// KR-REQ-11.42, KR-REQ-18.06: a package the organisation's adapter allowlist does not name
    /// keeps no registration, and lifting the list, or naming the package, puts it back. The
    /// controls are a list that names the package and no list at all.
    ///
    /// Windows applies no native bridge (`refused_on_windows`), so this runs on the other
    /// platforms.
    #[cfg(unix)]
    #[tokio::test]
    async fn kr_req_11_42_a_package_the_allowlist_does_not_name_keeps_no_registration() {
        let site = Site::new();
        let host = host(&site);
        let digest = synchronised(&host).await;
        let before = site.tree();
        let _: wire::PluginInstallResult = installed_and_enabled(&host, &digest).await;
        let placed = applied(&before, &host.working);
        assert_eq!(site.tree(), placed, "applied");

        let naming = |name: &str| {
            Some(std::collections::BTreeSet::from([
                PluginId::new(name).expect("a plugin identifier")
            ]))
        };
        let put = |set| async { host.module.put_allowed_adapters(set).await.expect("put") };

        assert!(put(naming("kalareach/claude-code")).await);
        assert_eq!(site.tree(), placed, "a list that names it leaves it");
        assert!(bridge_facts(&host, &digest).is_some());

        assert!(put(naming("kalareach/codex")).await);
        assert_eq!(
            site.tree(),
            before,
            "a list that does not name it takes it out"
        );
        assert!(bridge_facts(&host, &digest).is_none());
        {
            let catalogue = host.module.catalogue().lock().await;
            assert!(
                catalogue
                    .installation(host.environment_id, &claude_code())
                    .expect("readable")
                    .is_some(),
                "the installation stays"
            );
        }

        assert!(
            !put(naming("kalareach/codex")).await,
            "the same list moves nothing"
        );
        assert_eq!(site.tree(), before);
        assert!(put(None).await);
        assert_eq!(site.tree(), placed, "with no list it is back");
        assert!(bridge_facts(&host, &digest).is_some());
    }
    /// KR-REQ-11.42: the index that says whether a release is revoked is read last and once, so a
    /// package the owner disabled or the organisation's list excludes loses its registration with
    /// the index unreadable, and where the index is what cannot be read nothing is known to stand
    /// and the registration is not kept on its account. The control is the index repaired: the
    /// registration comes back with the next change that follows bridges.
    ///
    /// Windows applies no native bridge (`refused_on_windows`), so this runs on the other
    /// platforms.
    #[cfg(unix)]
    #[tokio::test]
    async fn kr_req_11_42_an_unreadable_index_keeps_no_registration_and_a_repaired_one_restores_it()
    {
        let site = Site::new();
        let host = host(&site);
        let digest = synchronised(&host).await;
        let before = site.tree();
        let _: wire::PluginInstallResult = installed_and_enabled(&host, &digest).await;
        let placed = applied(&before, &host.working);
        assert_eq!(site.tree(), placed, "applied");

        let index = {
            let catalogue = host.module.catalogue().lock().await;
            let id = RepositoryId::new("development").expect("a valid identifier");
            let active = catalogue
                .repository_views()
                .expect("readable")
                .into_iter()
                .find(|view| view.enrolment.id == id)
                .and_then(|view| view.active)
                .expect("an activated generation");
            catalogue
                .store(&id)
                .expect("enrolled")
                .index_path(active.index_digest)
        };
        let intact = std::fs::read(&index).expect("the index");
        let name = |name: &str| {
            Some(std::collections::BTreeSet::from([
                PluginId::new(name).expect("a plugin identifier")
            ]))
        };

        // The list excludes the package while the index is damaged: the registration goes.
        std::fs::write(&index, b"not an index").expect("damaged");
        assert!(
            host.module
                .put_allowed_adapters(name("kalareach/codex"))
                .await
                .expect("put")
        );
        assert_eq!(
            site.tree(),
            before,
            "a package the list excludes loses its registration whatever state the index is in"
        );

        // The list lifted and the index still damaged: nothing says the release stands.
        assert!(host.module.put_allowed_adapters(None).await.expect("put"));
        assert_eq!(
            site.tree(),
            before,
            "a registration is not put back on an index that cannot be read"
        );

        // Control: repaired, the next change that follows bridges puts it back.
        std::fs::write(&index, &intact).expect("repaired");
        assert!(
            host.module
                .put_allowed_adapters(name("kalareach/claude-code"))
                .await
                .expect("put")
        );
        assert_eq!(site.tree(), placed, "the repaired index restores it");
    }

    /// KR-REQ-11.42: the organisation's list is in force when the catalogue opens, before any
    /// bridge is brought to what its installation wants, so a restart puts back no registration
    /// the list excludes. The control is a restart with no list, which puts it back.
    ///
    /// Windows applies no native bridge (`refused_on_windows`), so this runs on the other
    /// platforms.
    #[cfg(unix)]
    #[tokio::test]
    async fn kr_req_11_42_a_restart_under_the_allowlist_puts_back_no_excluded_registration() {
        let site = Site::new();
        let mut host = host(&site);
        let digest = synchronised(&host).await;
        let before = site.tree();
        let _: wire::PluginInstallResult = installed_and_enabled(&host, &digest).await;
        let placed = applied(&before, &host.working);
        let list = Some(std::collections::BTreeSet::from([PluginId::new(
            "kalareach/codex",
        )
        .expect("a plugin identifier")]));
        assert!(
            host.module
                .put_allowed_adapters(list.clone())
                .await
                .expect("put")
        );
        assert_eq!(site.tree(), before, "excluded");

        let environment = host._temp.environment();
        let open = |allowed| {
            CatalogueModule::open_with(
                &environment,
                None,
                site.bridges(&environment),
                Arc::new(kr_plugin_catalogue::UnboundBroker),
                kr_protocol::hostinfo::configuration::EnrolmentBudgets::default(),
                None,
                allowed,
            )
            .expect("an openable catalogue")
        };
        host.module = open(list);
        assert_eq!(
            site.tree(),
            before,
            "the restarted daemon leaves an excluded package's registration out"
        );
        assert!(bridge_facts(&host, &digest).is_none());

        host.module = open(None);
        assert_eq!(site.tree(), placed, "with no list the start puts it back");
    }
}
