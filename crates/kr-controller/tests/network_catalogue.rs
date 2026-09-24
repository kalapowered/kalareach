//! The two plugin method groups over the network path.
//!
//! What these demonstrate, towards KR-REQ-23.28 and KR-REQ-23.29 for the paired-device ingress.
//! The registry admits a device to all thirteen methods; until now the network dispatcher refused
//! the three reads as unsupported and sent the ten mutations to the worker proxy, which wants a
//! session a catalogue mutation does not name.
//!
//! A catalogue and an installed package belong to the environment, so the daemon answers all
//! thirteen itself and a device is given what the owner's own socket is given. What is additionally
//! held against a device is its grant, the subject check that keeps a receipt from naming a session
//! the effect never touched, and the owner's own ceremony for the two confirmed methods: the
//! challenge is the host's, and the ledger consumes it exactly once.
//!
//! No worker is started here. The catalogue is a copy of the published development generation, made
//! on the internal disk before anything opens it.

mod net_support;

use std::path::Path;

use kr_client::session::Session;
use kr_controller::sharing::{CatalogueTrustPlan, PluginGrantPlan};
use kr_crypto::keys::DeviceKeys;
use kr_plugin_catalogue::{CapabilityCeiling, Enrolment, RepositoryId, RepositoryKind};
use kr_protocol::catalogue as wire;
use kr_protocol::envelope::{ActionTarget, ParamsValue};
use kr_protocol::error::{ErrorCode, ProtocolError};
use kr_protocol::ids::{EnvironmentId, PluginId, RepositoryGeneration};
use kr_protocol::method::Method;
use kr_protocol::pairing::SensitiveAction;
use kr_protocol::rights::ActionRight;
use kr_protocol::scalars::{DurationMs, Nullable, U64};
use net_support::Host;

/// The rights a device needs to reach every catalogue and plugin method.
const CATALOGUE_RIGHTS: &[ActionRight] = &[ActionRight::HostManage];

/// How long a mutation asks for. A sync verifies metadata and an installation extracts a package.
const LIFETIME: DurationMs = DurationMs::new(120_000);

/// Where the published development generation lives inside this checkout.
fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/plugins/catalogue/development")
}

fn plugin() -> PluginId {
    PluginId::new("kalareach/example-declarative").expect("a valid plugin identifier")
}

/// Runs one read over the network.
async fn remote_read<P, R>(
    session: &Session,
    method: Method,
    params: &P,
) -> Result<R, ProtocolError>
where
    P: serde::Serialize + ?Sized,
    R: kr_protocol::wire::WireMessage,
{
    session.read(method, params).await.map_err(client_refusal)
}

/// Runs one mutation over the network, and returns whatever the daemon answered.
async fn remote_mutation<P>(
    session: &Session,
    environment_id: EnvironmentId,
    method: Method,
    params: &P,
) -> Result<ParamsValue, ProtocolError>
where
    P: serde::Serialize + ?Sized,
{
    session
        .mutate(
            method,
            ActionTarget::environment(environment_id),
            None,
            &ParamsValue::empty(),
            params,
            LIFETIME,
        )
        .await
        .map_err(client_refusal)
        .map(|settled| {
            settled
                .result()
                .cloned()
                .expect("a catalogue mutation answers with its result")
        })
}

/// The host's own refusal, out of whatever the client wrapped it in.
fn client_refusal(error: kr_client::error::ClientError) -> ProtocolError {
    match error {
        kr_client::error::ClientError::Host(error) => error,
        other => panic!("the host refused with something else: {other:?}"),
    }
}

fn typed<T: kr_protocol::wire::WireMessage>(value: &ParamsValue) -> T {
    value.to_typed().expect("a result of the declared shape")
}

/// A copy of the published generation, on the internal disk.
struct Published {
    _temp: tempfile::TempDir,
    root: std::path::PathBuf,
}

impl Published {
    fn create() -> Self {
        let temp = tempfile::tempdir().expect("a temporary directory on the internal disk");
        let root = temp.path().join("development");
        copy_tree(&fixture(), &root);
        Self { _temp: temp, root }
    }

    /// The manifest digest one entry of the published index declares.
    ///
    /// A device learns a package's hash from the generation it verified. Reading it out of the
    /// same published bytes the daemon verifies is what lets this suite name the exact package
    /// `plugin.install` will be given.
    fn manifest_digest(&self, plugin_id: &PluginId, version: &str) -> String {
        let index: serde_json::Value = serde_json::from_slice(
            &std::fs::read(self.root.join("targets/index.json")).expect("a published index"),
        )
        .expect("a readable index");
        index["entries"]
            .as_array()
            .expect("the index lists entries")
            .iter()
            .find(|entry| entry["plugin_id"] == plugin_id.as_str() && entry["version"] == version)
            .expect("the published index names this package")["manifest_digest"]
            .as_str()
            .expect("a digest")
            .to_owned()
    }

    fn metadata_url(&self) -> String {
        directory_url(&self.root.join("metadata"))
    }

    fn targets_url(&self) -> String {
        directory_url(&self.root.join("targets"))
    }

    fn root_bytes(&self) -> Vec<u8> {
        std::fs::read(self.root.join("root.json")).expect("a trust root")
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

/// The parameters of a `catalogue.add`, with the owner's confirmation of that exact enrolment.
fn add_params(host: &Host, owner: &DeviceKeys, published: &Published) -> wire::CatalogueAddParams {
    use base64::Engine as _;
    let root = published.root_bytes();
    let metadata_url = published.metadata_url();
    let targets_url = published.targets_url();
    // The owner is asked about this exact enrolment: this repository, this root and this ceiling.
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
        owner_confirmation: host.confirm(owner, SensitiveAction::TrustRepositoryRoot, digest),
    }
}

/// The parameters of a `plugin.grant`, with the owner's confirmation of that exact grant.
fn grant_params(
    host: &Host,
    owner: &DeviceKeys,
    package_digest: &str,
    grant: Vec<String>,
) -> wire::PluginGrantParams {
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
        owner_confirmation: host.confirm(owner, SensitiveAction::GrantExecutableCapability, digest),
    }
}

// ---------------------------------------------------------------------------------------------
// KR-REQ-23.28 and KR-REQ-23.29 at the paired-device ingress
// ---------------------------------------------------------------------------------------------

/// Every one of the thirteen methods answers a paired device, and answers it about this host.
///
/// The order is the product order: trust a root, synchronise a generation, install a package from
/// it, enable it, read what it can do, and take all of it away again.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn kr_req_23_28_and_23_29_a_paired_device_reaches_every_catalogue_and_plugin_method() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, session) = net_support::paired_device(&host, &owner, CATALOGUE_RIGHTS).await;
    let published = Published::create();
    let environment_id = host.environment_id;

    // Nothing is enrolled, and the device is told so rather than being refused the method.
    let listed: wire::CatalogueListResult = typed(
        &remote_read::<_, ParamsValue>(
            &session,
            Method::CatalogueList,
            &wire::CatalogueListParams { environment_id },
        )
        .await
        .expect("catalogue.list answers a device"),
    );
    assert!(listed.catalogues.is_empty());

    // catalogue.add, under the owner's confirmation of this exact root.
    let added: wire::CatalogueAddResult = typed(
        &remote_mutation(
            &session,
            environment_id,
            Method::CatalogueAdd,
            &add_params(&host, &owner, &published),
        )
        .await
        .expect("catalogue.add answers a device"),
    );
    assert_eq!(added.catalogue.catalogue_id, "development");
    assert_eq!(added.catalogue.generation, Nullable(None));

    // catalogue.sync verifies the published generation and activates its index.
    let synced: wire::CatalogueSyncResult = typed(
        &remote_mutation(
            &session,
            environment_id,
            Method::CatalogueSync,
            &wire::CatalogueSyncParams {
                environment_id,
                catalogue_id: "development".to_owned(),
            },
        )
        .await
        .expect("catalogue.sync answers a device"),
    );
    assert_eq!(synced.generation.get(), 1);
    assert_eq!(synced.entries, U64::new(7));

    // catalogue.list now describes what this host trusts.
    let listed: wire::CatalogueListResult = typed(
        &remote_read::<_, ParamsValue>(
            &session,
            Method::CatalogueList,
            &wire::CatalogueListParams { environment_id },
        )
        .await
        .expect("catalogue.list answers a device"),
    );
    assert_eq!(listed.catalogues.len(), 1);
    assert_eq!(
        listed.catalogues[0].generation,
        Nullable(Some(RepositoryGeneration::new(1)))
    );

    // catalogue.pin holds it at the generation the device read.
    let pinned: wire::CataloguePinResult = typed(
        &remote_mutation(
            &session,
            environment_id,
            Method::CataloguePin,
            &wire::CataloguePinParams {
                environment_id,
                catalogue_id: "development".to_owned(),
                generation: Nullable(Some(RepositoryGeneration::new(1))),
            },
        )
        .await
        .expect("catalogue.pin answers a device"),
    );
    assert_eq!(
        pinned.catalogue.pinned_generation,
        Nullable(Some(RepositoryGeneration::new(1)))
    );

    // plugin.install, on the exact hash the verified generation declares.
    let package_digest = published.manifest_digest(&plugin(), "0.1.0");
    let installed: wire::PluginInstallResult = typed(
        &remote_mutation(
            &session,
            environment_id,
            Method::PluginInstall,
            &wire::PluginInstallParams {
                environment_id,
                catalogue_id: "development".to_owned(),
                plugin_id: plugin(),
                version: "0.1.0".to_owned(),
                package_digest: package_digest.clone(),
                grant: Vec::new(),
                owner_confirmation: Nullable::null(),
            },
        )
        .await
        .expect("plugin.install answers a device"),
    );
    assert_eq!(installed.plugin.package_digest, package_digest);
    assert!(!installed.plugin.enabled, "installing does not enable");

    // plugin.enable and plugin.pin.
    let enabled: wire::PluginEnableResult = typed(
        &remote_mutation(
            &session,
            environment_id,
            Method::PluginEnable,
            &wire::PluginEnableParams {
                environment_id,
                plugin_id: plugin(),
            },
        )
        .await
        .expect("plugin.enable answers a device"),
    );
    assert!(enabled.plugin.enabled);

    let held: wire::PluginPinResult = typed(
        &remote_mutation(
            &session,
            environment_id,
            Method::PluginPin,
            &wire::PluginPinParams {
                environment_id,
                plugin_id: plugin(),
                package_digest: Nullable(Some(package_digest.clone())),
            },
        )
        .await
        .expect("plugin.pin answers a device"),
    );
    assert!(held.plugin.pinned);

    // plugin.list and the scoped capability query. The evidence names the exact package hash the
    // installation is on, which is what makes the answer about this installation rather than about
    // whatever the repository now publishes.
    let plugins: wire::PluginListResult = typed(
        &remote_read::<_, ParamsValue>(
            &session,
            Method::PluginList,
            &wire::PluginListParams { environment_id },
        )
        .await
        .expect("plugin.list answers a device"),
    );
    assert_eq!(plugins.plugins.len(), 1);
    assert_eq!(plugins.plugins[0].catalogue_id, "development");

    let capabilities: wire::PluginCapabilitiesResult = typed(
        &remote_read::<_, ParamsValue>(
            &session,
            Method::PluginCapabilities,
            &wire::PluginCapabilitiesParams {
                environment_id,
                plugin_id: plugin(),
            },
        )
        .await
        .expect("plugin.capabilities answers a device"),
    );
    assert_eq!(capabilities.plugin.package_digest, package_digest);
    assert_eq!(
        capabilities.capabilities.len(),
        capabilities.evidence.len(),
        "every requested capability has an answer"
    );
    for record in &capabilities.evidence {
        assert_eq!(
            record.package_digest, package_digest,
            "evidence names the exact package hash it is about"
        );
    }

    // plugin.grant completes over the network, under the owner's confirmation of that exact
    // grant: the capability is one the package asks for and the repository's ceiling reaches.
    let granted: wire::PluginGrantResult = typed(
        &remote_mutation(
            &session,
            environment_id,
            Method::PluginGrant,
            &grant_params(
                &host,
                &owner,
                &package_digest,
                vec!["broker.semantic_events".to_owned()],
            ),
        )
        .await
        .expect("plugin.grant answers a device"),
    );
    assert!(
        granted.capabilities.iter().any(|grant| {
            grant.capability.as_str().contains("broker.semantic_events") && grant.permitted
        }),
        "{granted:?}"
    );

    // And it reaches the module's own decision: a capability this package does not ask for is
    // refused by name, which nothing in the dispatcher knows how to say.
    let refused = remote_mutation(
        &session,
        environment_id,
        Method::PluginGrant,
        &grant_params(
            &host,
            &owner,
            &package_digest,
            vec!["filesystem.read".to_owned()],
        ),
    )
    .await
    .expect_err("this package does not ask for filesystem.read");
    assert_eq!(refused.code, ErrorCode::PluginGrantRequired, "{refused:?}");
    assert!(
        refused.message.contains("does not request filesystem.read"),
        "{refused:?}"
    );

    // An owner confirmation this host never issued authorises nothing, whichever door it arrives
    // at: the challenge in the proof has to be one this host's own ledger is still holding.
    let mut forged = grant_params(
        &host,
        &owner,
        &package_digest,
        vec!["broker.semantic_events".to_owned()],
    );
    forged.owner_confirmation = host.confirm(
        &owner,
        SensitiveAction::GrantExecutableCapability,
        kr_protocol::scalars::Digest256::from_bytes([9u8; 32]),
    );
    let refused = remote_mutation(&session, environment_id, Method::PluginGrant, &forged)
        .await
        .expect_err("a confirmation of another action grants nothing");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");

    // plugin.disable, plugin.remove and catalogue.remove.
    let disabled: wire::PluginEnableResult = typed(
        &remote_mutation(
            &session,
            environment_id,
            Method::PluginDisable,
            &wire::PluginEnableParams {
                environment_id,
                plugin_id: plugin(),
            },
        )
        .await
        .expect("plugin.disable answers a device"),
    );
    assert!(!disabled.plugin.enabled);

    let removed: wire::PluginRemoveResult = typed(
        &remote_mutation(
            &session,
            environment_id,
            Method::PluginRemove,
            &wire::PluginRemoveParams {
                environment_id,
                plugin_id: plugin(),
            },
        )
        .await
        .expect("plugin.remove answers a device"),
    );
    assert_eq!(removed.plugin_id, plugin());

    let dropped: wire::CatalogueRemoveResult = typed(
        &remote_mutation(
            &session,
            environment_id,
            Method::CatalogueRemove,
            &wire::CatalogueRemoveParams {
                environment_id,
                catalogue_id: "development".to_owned(),
            },
        )
        .await
        .expect("catalogue.remove answers a device"),
    );
    assert_eq!(dropped.catalogue_id, "development");
    assert!(dropped.installed_packages.is_empty());

    session.close();
    host.stop().await;
}

/// A device's catalogue mutation is held to the subject rule the owner's own door applies.
///
/// A target naming a session would produce a receipt against something the effect never touched,
/// and the parameters have to name the environment the target names.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_catalogue_mutation_from_a_device_names_an_environment_and_never_a_session() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, session) = net_support::paired_device(&host, &owner, CATALOGUE_RIGHTS).await;
    let environment_id = host.environment_id;

    // A complete session target, so what refuses it is the subject rule rather than an envelope
    // that named half a session.
    let mut target = ActionTarget::environment(environment_id);
    target.session_id = Nullable(Some(kr_protocol::ids::SessionId::new(kr_ipc::new_uuid())));
    target.session_epoch = Nullable(Some(kr_protocol::ids::SessionEpoch::new(1)));
    let refused = session
        .mutate(
            Method::CatalogueSync,
            target,
            None,
            &ParamsValue::empty(),
            &wire::CatalogueSyncParams {
                environment_id,
                catalogue_id: "development".to_owned(),
            },
            LIFETIME,
        )
        .await
        .map(|_| ())
        .expect_err("a catalogue acts on no session");
    let refused = client_refusal(refused);
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");
    assert!(
        refused.message.contains("not on a session"),
        "the refusal names the subject rule: {refused:?}"
    );

    session.close();
    host.stop().await;
}

/// The registry decides what a device without `host.manage` reaches, and the daemon holds it there.
///
/// Both groups are admitted at this ingress, so what keeps a device out of them is the rights its
/// grant carries. Every mutation and `catalogue.list` require `host.manage`; `plugin.list` and
/// `plugin.capabilities` require no right at all, and a device that holds none still reads them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn what_a_device_without_host_manage_reaches_is_what_the_registry_lists() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, session) =
        net_support::paired_device(&host, &owner, &[ActionRight::SessionView]).await;
    let environment_id = host.environment_id;

    let refused = remote_read::<_, ParamsValue>(
        &session,
        Method::CatalogueList,
        &wire::CatalogueListParams { environment_id },
    )
    .await
    .expect_err("catalogue.list needs host.manage");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");

    for method in [
        Method::CatalogueSync,
        Method::CatalogueRemove,
        Method::PluginEnable,
    ] {
        let refused = session
            .mutate(
                method,
                ActionTarget::environment(environment_id),
                None,
                &ParamsValue::empty(),
                &wire::CatalogueSyncParams {
                    environment_id,
                    catalogue_id: "development".to_owned(),
                },
                LIFETIME,
            )
            .await
            .map(|_| ())
            .expect_err("every mutation in both groups needs host.manage");
        let refused = client_refusal(refused);
        assert_eq!(
            refused.code,
            ErrorCode::PermissionDenied,
            "{}: {refused:?}",
            method.as_str()
        );
    }

    // The two reads the registry lists with no required right answer this device.
    let plugins: wire::PluginListResult = typed(
        &remote_read::<_, ParamsValue>(
            &session,
            Method::PluginList,
            &wire::PluginListParams { environment_id },
        )
        .await
        .expect("plugin.list requires no right"),
    );
    assert!(plugins.plugins.is_empty());

    // And an environment this daemon does not own is refused before anything is read.
    let refused = remote_read::<_, ParamsValue>(
        &session,
        Method::PluginList,
        &wire::PluginListParams {
            environment_id: EnvironmentId::new(kr_ipc::new_uuid()),
        },
    )
    .await
    .expect_err("this daemon owns one environment");
    assert_eq!(refused.code, ErrorCode::InvalidArgument, "{refused:?}");

    session.close();
    host.stop().await;
}

/// A device that submits the same catalogue action twice is given its first answer back.
///
/// The receipt lives with the catalogue, beside the state the effect changed, so the answer comes
/// from the record that effect settled rather than from performing it a second time.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_resubmitted_catalogue_action_is_answered_from_its_own_record() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let device = net_support::Device::create().await;
    let record = net_support::pair_with(
        &host,
        &device,
        &owner,
        net_support::proposal(CATALOGUE_RIGHTS),
    )
    .await;
    let raw = net_support::RawDevice::connect(&host, &device, &record).await;
    raw.claim();
    let published = Published::create();
    let environment_id = host.environment_id;

    let action_id = kr_protocol::ids::ActionId::new(kr_ipc::new_uuid());
    let params = add_params(&host, &owner, &published);
    let submitted_at = kr_ipc::now_ms().get();
    let first: wire::CatalogueAddResult = typed(
        &raw.mutate(
            Method::CatalogueAdd,
            action_id,
            ActionTarget::environment(environment_id),
            &params,
        )
        .await
        .expect("catalogue.add answers a device"),
    );
    let read_receipt = || async {
        typed::<kr_protocol::receipt::ActionReadResult>(
            &raw.read(
                Method::ActionRead,
                &kr_protocol::receipt::ActionReadParams {
                    action_id,
                    session_id: None,
                },
            )
            .await
            .expect("action.read answers for a catalogue action"),
        )
    };
    // The receipt keeps the deadline the daemon accepted the action under, which is inside the
    // lifetime the device asked for.
    let accepted = read_receipt().await;
    let deadline = accepted
        .receipt
        .accepted_deadline_ms
        .0
        .expect("the deadline the action was accepted under")
        .get();
    assert!(
        deadline > submitted_at && deadline <= kr_ipc::now_ms().get() + 120_000,
        "{deadline} is inside the lifetime asked for at {submitted_at}"
    );

    // The same identity and the same payload. A second enrolment of one root is refused, so an
    // answer that repeats the first can only have come from the record the first settled.
    let again: wire::CatalogueAddResult = typed(
        &raw.mutate(
            Method::CatalogueAdd,
            action_id,
            ActionTarget::environment(environment_id),
            &params,
        )
        .await
        .expect("the resubmission is answered rather than performed"),
    );
    assert_eq!(again.catalogue.catalogue_id, first.catalogue.catalogue_id);
    assert_eq!(again.catalogue.root_digest, first.catalogue.root_digest);

    // The receipt is readable where the action was: it names no session, so the catalogue that
    // performed the action answers, with the state it settled in and the answer it gave. The
    // resubmission moved nothing in it, the accepted deadline included.
    let read = read_receipt().await;
    assert_eq!(read.receipt, accepted.receipt);
    assert_eq!(
        read.receipt.state,
        kr_protocol::receipt::ReceiptState::Applied
    );
    assert_eq!(read.receipt.action_id, action_id);
    let retained: wire::CatalogueAddResult =
        typed(read.result.0.as_ref().expect("the retained answer"));
    assert_eq!(retained.catalogue.root_digest, first.catalogue.root_digest);

    raw.close();
    host.stop().await;
}

/// KR-REQ-10.05: the catalogue's confirmed decisions are this host's owner's, confirmed on its owner
/// devices and on nothing else. A proof of exactly this enrolment signed with a key that is not an
/// owner device's is refused and trusts nothing; the owner device's own proof then trusts it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_catalogue_decision_is_confirmed_by_an_owner_device_and_by_nothing_else() {
    let owner = DeviceKeys::generate().expect("owner keys");
    let host = Host::start(&owner).await;
    let (_device, session) = net_support::paired_device(&host, &owner, CATALOGUE_RIGHTS).await;
    let published = Published::create();
    let environment_id = host.environment_id;

    let stranger = DeviceKeys::generate().expect("keys that are no owner device's");
    let refused = remote_mutation(
        &session,
        environment_id,
        Method::CatalogueAdd,
        &add_params(&host, &stranger, &published),
    )
    .await
    .expect_err("a key that is no owner device's confirms nothing");
    assert_eq!(refused.code, ErrorCode::PermissionDenied, "{refused:?}");
    let listed: wire::CatalogueListResult = typed(
        &remote_read::<_, ParamsValue>(
            &session,
            Method::CatalogueList,
            &wire::CatalogueListParams { environment_id },
        )
        .await
        .expect("catalogue.list answers a device"),
    );
    assert!(listed.catalogues.is_empty(), "nothing was trusted");

    let _: wire::CatalogueAddResult = typed(
        &remote_mutation(
            &session,
            environment_id,
            Method::CatalogueAdd,
            &add_params(&host, &owner, &published),
        )
        .await
        .expect("the owner device's own proof trusts it"),
    );
    host.stop().await;
}
