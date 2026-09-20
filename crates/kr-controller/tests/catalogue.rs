//! The two plugin method groups, as the control daemon serves them.
//!
//! The catalogue's own rules are the runtime crate's and are tested there. What this covers is the
//! daemon's half: that both groups reach the module at all, that every method in them has one
//! exhaustive generated authority entry, that a request for another environment is refused before
//! anything is read, and that the answers carry the checks section 23 names for those two rows.

use std::path::Path;

use kr_controller::catalogue::CatalogueModule;
use kr_controller::sharing::{
    CatalogueTrustPlan, ConfirmedAction, OwnerConfirmations, PluginGrantPlan,
};
use kr_plugin_runtime::catalogue::{CapabilityCeiling, Enrolment, RepositoryId, RepositoryKind};
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
#[derive(Debug)]
struct Clock;

impl kr_pairing::platform::PairingClock for Clock {
    fn monotonic_ms(&self) -> u64 {
        kr_ipc::clock::SharedClock::boot_elapsed_ms(&kr_ipc::clock::SystemSharedClock)
    }

    fn boot_identity(&self) -> kr_pairing::platform::BootIdentity {
        let value = kr_ipc::identity::boot_identity()
            .map(|identity| identity.value.as_slice().to_vec())
            .unwrap_or_default();
        kr_pairing::platform::BootIdentity(kr_cbor::sha256(&value))
    }

    fn wall_clock_ms(&self) -> u64 {
        kr_ipc::now_ms().get()
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
}

impl Ceremony {
    fn new() -> Self {
        Self {
            owner: kr_crypto::keys::AuthorisationKeyPair::generate().expect("an owner key"),
            ledger: std::sync::Mutex::new(kr_pairing::confirm::ConfirmationLedger::new()),
            clock: Clock,
            device_id: kr_protocol::ids::DeviceId::new(kr_ipc::new_uuid()),
            endpoint_id: kr_protocol::scalars::EndpointKey::from_bytes([7u8; 32]),
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
        ConfirmedAction::verify(
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
        )
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
        payload_cache_bytes: defaults.payload_cache_bytes,
        full_offline_mirror: false,
    }
}

fn add_params(host: &Host) -> wire::CatalogueAddParams {
    use base64::Engine as _;
    let root = std::fs::read(host.working.join("root.json")).expect("a trust root");
    let metadata_url = directory_url(&host.working.join("metadata"));
    let targets_url = directory_url(&host.working.join("targets"));
    // The owner is asked about this exact enrolment: this repository, this root and this ceiling.
    // The client builds the plan the host will build, which is what makes the digests agree.
    let digest = CatalogueTrustPlan {
        environment_id: host.environment_id,
        catalogue_id: "development".to_owned(),
        root_digest: kr_plugin_sdk::digest::PayloadDigest::of(&root).to_string(),
        root_key_ids: root_key_ids(&root, &metadata_url, &targets_url),
        ceiling: kr_protocol::scalars::CanonicalSet::new(),
    }
    .action_digest()
    .expect("a digest");
    wire::CatalogueAddParams {
        environment_id: host.environment_id,
        catalogue_id: "development".to_owned(),
        kind: wire::CatalogueKind::Local,
        metadata_url,
        targets_url,
        root: base64::engine::general_purpose::STANDARD.encode(&root),
        budgets: budgets(),
        ceiling: Vec::new(),
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
        .read_frame(&request(
            Method::CatalogueList,
            &wire::CatalogueListParams {
                environment_id: host.environment_id,
            },
        ))
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
            .read_frame(&request(
                Method::CatalogueList,
                &wire::CatalogueListParams {
                    environment_id: other,
                },
            ))
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
        let id = kr_plugin_runtime::catalogue::RepositoryId::new("development")
            .expect("a valid identifier");
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
                    },
                ),
                Method::PluginInstall,
                Some(host.confirmations()),
            )
            .await,
    );
    assert_eq!(wrong.code, ErrorCode::AttachmentIntegrity);

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
        .read_frame(&request(
            Method::PluginList,
            &wire::PluginListParams {
                environment_id: host.environment_id,
            },
        ))
        .await);
    assert_eq!(listed.plugins.len(), 1);
    assert_eq!(listed.plugins[0].catalogue_id, "development");
    assert_eq!(listed.plugins[0].live_bindings, U64::new(0));

    let capabilities: wire::PluginCapabilitiesResult = ok(host
        .module
        .read_frame(&request(
            Method::PluginCapabilities,
            &wire::PluginCapabilitiesParams {
                environment_id: host.environment_id,
                plugin_id: plugin(),
            },
        ))
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
        let id = kr_plugin_runtime::catalogue::RepositoryId::new("development")
            .expect("a valid identifier");
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
        .read_frame(&request(
            Method::PluginList,
            &wire::PluginListParams {
                environment_id: host.environment_id,
            },
        ))
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
    let refused = client
        .mutate(
            Method::CatalogueSync,
            ActionId::new(kr_ipc::new_uuid()),
            target.clone(),
            &wire::CatalogueSyncParams {
                environment_id,
                catalogue_id: "development".to_owned(),
            },
        )
        .await
        .expect("the call reaches the daemon")
        .expect_err("nothing is enrolled yet");
    assert_eq!(refused.code, ErrorCode::ResourceUnavailable, "{refused:?}");

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
            || Ok(()),
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
            || Ok(()),
        )
        .await;
    let added2: wire::CatalogueAddResult = ok(outcome2);
    assert_eq!(added2.catalogue.catalogue_id, "development");

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
                || Ok(()),
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
                || {
                    Err(kr_protocol::error::ProtocolError::new(
                        ErrorCode::PermissionDenied,
                        "window expired",
                    ))
                },
            )
            .await,
    );
    assert_eq!(expired.code, ErrorCode::PermissionDenied);
}
